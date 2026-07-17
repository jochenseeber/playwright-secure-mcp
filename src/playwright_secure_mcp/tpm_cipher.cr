{% if flag?(:linux) %}
  require "random/secure"
  require "./secret_cipher"
  require "./encrypted_secret"
  require "./aes_cbc"

  module PlaywrightSecureMcp
    # Seals a 32-byte AES data key inside the platform TPM 2.0 using the
    # tpm2-tss ESYS (Enhanced System API) C library over the kernel resource
    # manager device /dev/tpmrm0. The data key never touches disk; it is
    # unsealed transiently per batch via TPM2_Unseal, AES itself runs
    # in-process via `AesCbc`, and the unsealed key is zeroed after each use.
    #
    # Flow (mirrors the tpm2-tools seal/unseal recipe):
    #   Tss2_Tcti_Device_Init -> Esys_Initialize
    #   -> Esys_CreatePrimary (RSA-2048 restricted storage parent under OWNER)
    #   -> Esys_Create        (keyedhash sealed-data object holding K)
    #   -> Esys_Load          (load sealed object -> persistent-for-session ESYS_TR)
    #   -> Esys_Unseal        (per batch, transiently recover K)
    #
    # ABI WARNING: every `lib` struct/union below is ported by hand from the
    # tpm2-tss public headers and CANNOT be verified on this (macOS) build
    # host. Field order/size/alignment must match the C definitions exactly.
    # See the accompanying report for the per-struct citation and the list of
    # what must be re-verified on a Linux host with the tpm2-tss dev headers.
    class TpmCipher < SecretCipher
      class Error < Exception
      end

      DATA_KEY_SIZE = 32

      # --- tpm2-tss FFI ------------------------------------------------------
      #
      # Static libs assumed present on the Linux build host. Link order places
      # the higher layer (esys) first and its dependencies (tcti-device, mu,
      # sys) after, as required for static linking.
      @[Link("tss2-esys")]
      @[Link("tss2-tcti-device")]
      @[Link("tss2-mu")]
      @[Link("tss2-sys")]
      lib LibTss
        # ---- TPM2B_* and structured types (tss2_tpm2_types.h) --------------
        # Buffer capacities are the sizeof(...) expressions the header uses,
        # resolved to concrete constants (cited per struct). The union arms
        # kept below are the ones we construct/read; each union's declared
        # arms include the largest arm so the union's total size matches C.

        # TPM2B_DIGEST: { UINT16 size; BYTE buffer[sizeof(TPMU_HA)]; }
        # sizeof(TPMU_HA) == TPM2_SHA512_DIGEST_SIZE == 64. (tss2_tpm2_types.h)
        struct TPM2B_DIGEST
          size : UInt16
          buffer : UInt8[64]
        end

        # TPM2B_DATA: { UINT16 size; BYTE buffer[sizeof(TPMT_HA)]; }
        # sizeof(TPMT_HA) == 2 (hashAlg) + 64 (TPMU_HA) == 66. (tss2_tpm2_types.h)
        struct TPM2B_DATA
          size : UInt16
          buffer : UInt8[66]
        end

        # TPM2B_SENSITIVE_DATA: { UINT16 size; BYTE buffer[sizeof(TPMU_SENSITIVE_CREATE)]; }
        # sizeof(TPMU_SENSITIVE_CREATE) == TPM2_MAX_SYM_DATA == 128. (tss2_tpm2_types.h)
        struct TPM2B_SENSITIVE_DATA
          size : UInt16
          buffer : UInt8[128]
        end

        # TPM2B_PUBLIC_KEY_RSA: { UINT16 size; BYTE buffer[TPM2_MAX_RSA_KEY_BYTES]; }
        # TPM2_MAX_RSA_KEY_BYTES == 512. (tss2_tpm2_types.h)
        struct TPM2B_PUBLIC_KEY_RSA
          size : UInt16
          buffer : UInt8[512]
        end

        # TPMS_SENSITIVE_CREATE: { TPM2B_AUTH userAuth; TPM2B_SENSITIVE_DATA data; }
        # TPM2B_AUTH is a typedef of TPM2B_DIGEST. (tss2_tpm2_types.h)
        struct TPMS_SENSITIVE_CREATE
          user_auth : TPM2B_DIGEST
          data : TPM2B_SENSITIVE_DATA
        end

        # TPM2B_SENSITIVE_CREATE: { UINT16 size; TPMS_SENSITIVE_CREATE sensitive; }
        # (tss2_tpm2_types.h). `size` is recomputed by ESYS on marshal.
        struct TPM2B_SENSITIVE_CREATE
          size : UInt16
          sensitive : TPMS_SENSITIVE_CREATE
        end

        # TPMT_SYM_DEF_OBJECT:
        #   { TPMI_ALG_SYM_OBJECT algorithm;  # UINT16
        #     TPMU_SYM_KEY_BITS   keyBits;    # union, all arms UINT16 -> size 2
        #     TPMU_SYM_MODE       mode; }     # union, all arms UINT16 -> size 2
        # (tss2_tpm2_types.h)
        struct TPMT_SYM_DEF_OBJECT
          algorithm : UInt16
          key_bits : UInt16
          mode : UInt16
        end

        # TPMT_RSA_SCHEME: { TPMI_ALG_RSA_SCHEME scheme; TPMU_ASYM_SCHEME details; }
        # TPMU_ASYM_SCHEME's largest arm (TPMS_SCHEME_ECDAA: hashAlg+count) is
        # 4 bytes; represented as UInt16[2] so size/align (4/2) match.
        # scheme is set to TPM2_ALG_NULL, so `details` content is unused.
        struct TPMT_RSA_SCHEME
          scheme : UInt16
          details : UInt16[2]
        end

        # TPMS_RSA_PARMS:
        #   { TPMT_SYM_DEF_OBJECT symmetric; TPMT_RSA_SCHEME scheme;
        #     TPMI_RSA_KEY_BITS keyBits;    # UINT16
        #     UINT32 exponent; }
        # sizeof == 20 (exponent forces 4-byte alignment). (tss2_tpm2_types.h)
        struct TPMS_RSA_PARMS
          symmetric : TPMT_SYM_DEF_OBJECT
          scheme : TPMT_RSA_SCHEME
          key_bits : UInt16
          exponent : UInt32
        end

        # TPMT_KEYEDHASH_SCHEME: { TPMI_ALG_KEYEDHASH_SCHEME scheme; TPMU_SCHEME_KEYEDHASH details; }
        # TPMU_SCHEME_KEYEDHASH's largest arm (TPMS_SCHEME_XOR: hashAlg+kdf) is
        # 4 bytes; represented as UInt16[2]. scheme set to TPM2_ALG_NULL.
        struct TPMT_KEYEDHASH_SCHEME
          scheme : UInt16
          details : UInt16[2]
        end

        # TPMS_KEYEDHASH_PARMS: { TPMT_KEYEDHASH_SCHEME scheme; } (tss2_tpm2_types.h)
        struct TPMS_KEYEDHASH_PARMS
          scheme : TPMT_KEYEDHASH_SCHEME
        end

        # TPMU_PUBLIC_PARMS (tss2_tpm2_types.h). Full C union has keyedHashDetail,
        # symDetail, rsaDetail, eccDetail, asymDetail; rsaDetail (20 bytes) is the
        # largest, so declaring keyedHashDetail + rsaDetail yields the correct
        # union size (20) and alignment (4).
        union TPMU_PUBLIC_PARMS
          keyed_hash_detail : TPMS_KEYEDHASH_PARMS
          rsa_detail : TPMS_RSA_PARMS
        end

        # TPMU_PUBLIC_ID (tss2_tpm2_types.h). Full C union has keyedHash, sym,
        # rsa, ecc, derive; rsa (TPM2B_PUBLIC_KEY_RSA, 514 bytes) is the largest,
        # so declaring keyedHash + rsa yields the correct union size (514).
        union TPMU_PUBLIC_ID
          keyed_hash : TPM2B_DIGEST
          rsa : TPM2B_PUBLIC_KEY_RSA
        end

        # TPMT_PUBLIC (tss2_tpm2_types.h):
        #   { TPMI_ALG_PUBLIC type;         # UINT16
        #     TPMI_ALG_HASH   nameAlg;      # UINT16
        #     TPMA_OBJECT     objectAttributes;  # UINT32
        #     TPM2B_DIGEST    authPolicy;
        #     TPMU_PUBLIC_PARMS parameters;
        #     TPMU_PUBLIC_ID    unique; }
        # sizeof == 612.
        struct TPMT_PUBLIC
          type : UInt16
          name_alg : UInt16
          object_attributes : UInt32
          auth_policy : TPM2B_DIGEST
          parameters : TPMU_PUBLIC_PARMS
          unique : TPMU_PUBLIC_ID
        end

        # TPM2B_PUBLIC: { UINT16 size; TPMT_PUBLIC publicArea; } sizeof == 616.
        # `size` is recomputed by ESYS on marshal. (tss2_tpm2_types.h)
        struct TPM2B_PUBLIC
          size : UInt16
          public_area : TPMT_PUBLIC
        end

        # TPMS_PCR_SELECTION (tss2_tpm2_types.h):
        #   { TPMI_ALG_HASH hash; UINT8 sizeofSelect; BYTE pcrSelect[TPM2_PCR_SELECT_MAX]; }
        # TPM2_PCR_SELECT_MAX assumed 4; only `count`(=0) is read for our calls,
        # so the tail is never marshalled. See report for this assumption.
        struct TPMS_PCR_SELECTION
          hash : UInt16
          size_of_select : UInt8
          pcr_select : UInt8[4]
        end

        # TPML_PCR_SELECTION (tss2_tpm2_types.h):
        #   { UINT32 count; TPMS_PCR_SELECTION pcrSelections[TPM2_NUM_PCR_BANKS]; }
        # TPM2_NUM_PCR_BANKS == 16. We always pass count == 0 (empty selection).
        struct TPML_PCR_SELECTION
          count : UInt32
          pcr_selections : TPMS_PCR_SELECTION[16]
        end

        # ---- TCTI init (tss2_tcti_device.h) -------------------------------
        # TSS2_RC Tss2_Tcti_Device_Init(TSS2_TCTI_CONTEXT *tctiContext,
        #                               size_t *size, const char *conf);
        # Called first with tctiContext == NULL to obtain the required size,
        # then again with an allocated buffer to initialize it.
        fun Tss2_Tcti_Device_Init(
          tcti_context : Void*,
          size : LibC::SizeT*,
          conf : LibC::Char*,
        ) : UInt32

        # ---- ESYS (tss2_esys.h) -------------------------------------------
        # TSS2_RC Esys_Initialize(ESYS_CONTEXT **esys_context,
        #                         TSS2_TCTI_CONTEXT *tcti,
        #                         TSS2_ABI_VERSION *abiVersion);
        # abiVersion NULL => ESYS uses its compiled-in default.
        fun Esys_Initialize(
          esys_context : Void**,
          tcti : Void*,
          abi_version : Void*,
        ) : UInt32

        # void Esys_Finalize(ESYS_CONTEXT **context);
        fun Esys_Finalize(esys_context : Void**) : Void

        # void Esys_Free(void *ptr);
        fun Esys_Free(ptr : Void*) : Void

        # TSS2_RC Esys_FlushContext(ESYS_CONTEXT *esysContext, ESYS_TR flushHandle);
        fun Esys_FlushContext(esys_context : Void*, flush_handle : UInt32) : UInt32

        # TSS2_RC Esys_CreatePrimary(
        #   ESYS_CONTEXT *esysContext, ESYS_TR primaryHandle,
        #   ESYS_TR shandle1, shandle2, shandle3,
        #   const TPM2B_SENSITIVE_CREATE *inSensitive,
        #   const TPM2B_PUBLIC *inPublic,
        #   const TPM2B_DATA *outsideInfo,
        #   const TPML_PCR_SELECTION *creationPCR,
        #   ESYS_TR *objectHandle,
        #   TPM2B_PUBLIC **outPublic,
        #   TPM2B_CREATION_DATA **creationData,
        #   TPM2B_DIGEST **creationHash,
        #   TPMT_TK_CREATION **creationTicket);
        fun Esys_CreatePrimary(
          esys_context : Void*,
          primary_handle : UInt32,
          shandle1 : UInt32,
          shandle2 : UInt32,
          shandle3 : UInt32,
          in_sensitive : TPM2B_SENSITIVE_CREATE*,
          in_public : TPM2B_PUBLIC*,
          outside_info : TPM2B_DATA*,
          creation_pcr : TPML_PCR_SELECTION*,
          object_handle : UInt32*,
          out_public : Void**,
          creation_data : Void**,
          creation_hash : Void**,
          creation_ticket : Void**,
        ) : UInt32

        # TSS2_RC Esys_Create(
        #   ESYS_CONTEXT *esysContext, ESYS_TR parentHandle,
        #   ESYS_TR shandle1, shandle2, shandle3,
        #   const TPM2B_SENSITIVE_CREATE *inSensitive,
        #   const TPM2B_PUBLIC *inPublic,
        #   const TPM2B_DATA *outsideInfo,
        #   const TPML_PCR_SELECTION *creationPCR,
        #   TPM2B_PRIVATE **outPrivate, TPM2B_PUBLIC **outPublic,
        #   TPM2B_CREATION_DATA **creationData,
        #   TPM2B_DIGEST **creationHash, TPMT_TK_CREATION **creationTicket);
        fun Esys_Create(
          esys_context : Void*,
          parent_handle : UInt32,
          shandle1 : UInt32,
          shandle2 : UInt32,
          shandle3 : UInt32,
          in_sensitive : TPM2B_SENSITIVE_CREATE*,
          in_public : TPM2B_PUBLIC*,
          outside_info : TPM2B_DATA*,
          creation_pcr : TPML_PCR_SELECTION*,
          out_private : Void**,
          out_public : Void**,
          creation_data : Void**,
          creation_hash : Void**,
          creation_ticket : Void**,
        ) : UInt32

        # TSS2_RC Esys_Load(
        #   ESYS_CONTEXT *esysContext, ESYS_TR parentHandle,
        #   ESYS_TR shandle1, shandle2, shandle3,
        #   const TPM2B_PRIVATE *inPrivate, const TPM2B_PUBLIC *inPublic,
        #   ESYS_TR *objectHandle);
        # inPrivate/inPublic are the pointers ESYS allocated in Esys_Create,
        # passed through unchanged (typed Void* here).
        fun Esys_Load(
          esys_context : Void*,
          parent_handle : UInt32,
          shandle1 : UInt32,
          shandle2 : UInt32,
          shandle3 : UInt32,
          in_private : Void*,
          in_public : Void*,
          object_handle : UInt32*,
        ) : UInt32

        # TSS2_RC Esys_Unseal(
        #   ESYS_CONTEXT *esysContext, ESYS_TR itemHandle,
        #   ESYS_TR shandle1, shandle2, shandle3,
        #   TPM2B_SENSITIVE_DATA **outData);
        fun Esys_Unseal(
          esys_context : Void*,
          item_handle : UInt32,
          shandle1 : UInt32,
          shandle2 : UInt32,
          shandle3 : UInt32,
          out_data : Void**,
        ) : UInt32
      end

      # --- constants (values cited from the tpm2-tss headers) ---------------

      # tss2_common.h
      TSS2_RC_SUCCESS = 0_u32

      # ESYS_TR meta-handles (tss2_esys.h). ESYS_TR_RH_OWNER is the ESYS handle
      # that maps to TPM2_RH_OWNER (0x40000001); ESYS_TR_PASSWORD selects the
      # built-in empty-password session; ESYS_TR_NONE is the "no handle" marker.
      ESYS_TR_RH_OWNER =      0x101_u32
      ESYS_TR_PASSWORD =       0xFF_u32
      ESYS_TR_NONE     = 0xFFFFFFFF_u32

      # TPM2_ALG_ID values (tss2_tpm2_types.h)
      TPM2_ALG_RSA       = 0x0001_u16
      TPM2_ALG_KEYEDHASH = 0x0008_u16
      TPM2_ALG_AES       = 0x0006_u16
      TPM2_ALG_SHA256    = 0x000B_u16
      TPM2_ALG_NULL      = 0x0010_u16
      TPM2_ALG_CFB       = 0x0043_u16

      # TPMA_OBJECT attribute masks (tss2_tpm2_types.h):
      #   fixedTPM 0x2 | fixedParent 0x10 | sensitiveDataOrigin 0x20 |
      #   userWithAuth 0x40 | noDA 0x400 | restricted 0x10000 | decrypt 0x20000
      # Storage/parent (TCG "SRK"-style) template.
      RSA_STORAGE_ATTRIBUTES = 0x00030472_u32

      # Sealed-data (keyedhash) object: fixedTPM | fixedParent | userWithAuth.
      # NOT sensitiveDataOrigin (caller supplies the data), NOT sign/decrypt/
      # restricted, so it unseals under an empty-password session.
      SEALED_DATA_ATTRIBUTES = 0x00000052_u32

      @tcti_context : Pointer(UInt8)
      @esys_context : Void*
      @sealed_handle : UInt32

      def initialize
        @tcti_context = init_tcti
        @esys_context = init_esys(@tcti_context)
        @sealed_handle = seal_new_data_key
      end

      def encrypt(plaintext : Bytes) : EncryptedSecret
        with_data_key { |key| AesCbc.encrypt(key, plaintext) }
      end

      def decrypt(entry : EncryptedSecret) : Bytes
        with_data_key { |key| AesCbc.decrypt(key, entry) }
      end

      def decrypt_batch(entries : Array(EncryptedSecret)) : Array(Bytes)
        with_data_key { |key| entries.map { |entry| AesCbc.decrypt(key, entry) } }
      end

      def description : String
        "TPM 2.0"
      end

      # Unseals the data key for the duration of the block, then zeroes both
      # our copy and the ESYS-allocated buffer before freeing it.
      private def with_data_key(& : Bytes -> T) : T forall T
        out_data = Pointer(Void).null
        rc = LibTss.Esys_Unseal(
          @esys_context, @sealed_handle,
          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
          pointerof(out_data),
        )
        check(rc, "Esys_Unseal")
        raise Error.new("Esys_Unseal returned null outData") if out_data.null?

        # TPM2B_SENSITIVE_DATA is { UINT16 size; BYTE buffer[128] }: size is the
        # native-endian length (ESYS unmarshals to host order), buffer at +2.
        size = out_data.as(UInt16*).value.to_i
        source = out_data.as(UInt8*) + 2
        key = Bytes.new(size)
        source.copy_to(key.to_unsafe, size)
        begin
          yield key
        ensure
          key.fill(0_u8)
          source.clear(size)
          LibTss.Esys_Free(out_data)
        end
      end

      # Initializes the /dev/tpmrm0 device TCTI: query the context size, allocate
      # it, then initialize in place. The buffer is retained in @tcti_context for
      # the process lifetime because ESYS keeps a pointer into it.
      private def init_tcti : Pointer(UInt8)
        conf = "/dev/tpmrm0"
        size = LibC::SizeT.new(0)
        rc = LibTss.Tss2_Tcti_Device_Init(Pointer(Void).null, pointerof(size), conf)
        check(rc, "Tss2_Tcti_Device_Init(size query)")
        context = Pointer(UInt8).malloc(size)
        rc = LibTss.Tss2_Tcti_Device_Init(context.as(Void*), pointerof(size), conf)
        check(rc, "Tss2_Tcti_Device_Init")
        context
      end

      private def init_esys(tcti : Pointer(UInt8)) : Void*
        context = Pointer(Void).null
        rc = LibTss.Esys_Initialize(pointerof(context), tcti.as(Void*), Pointer(Void).null)
        check(rc, "Esys_Initialize")
        raise Error.new("Esys_Initialize returned null context") if context.null?
        context
      end

      # Creates the storage primary, generates and seals a fresh 32-byte data
      # key under it, loads the sealed object, and returns its ESYS_TR handle.
      # The primary is flushed once the sealed object is loaded.
      private def seal_new_data_key : UInt32
        primary = create_primary
        begin
          data_key = Random::Secure.random_bytes(DATA_KEY_SIZE)
          out_private = Pointer(Void).null
          out_public = Pointer(Void).null
          begin
            create_sealed(primary, data_key, pointerof(out_private), pointerof(out_public))
          ensure
            data_key.fill(0_u8)
          end
          begin
            load_sealed(primary, out_private, out_public)
          ensure
            LibTss.Esys_Free(out_private)
            LibTss.Esys_Free(out_public)
          end
        ensure
          LibTss.Esys_FlushContext(@esys_context, primary)
        end
      end

      private def create_primary : UInt32
        in_sensitive = empty_sensitive_create
        in_public = rsa_storage_template
        outside_info = LibTss::TPM2B_DATA.new
        creation_pcr = LibTss::TPML_PCR_SELECTION.new
        handle = 0_u32
        out_public = Pointer(Void).null
        creation_data = Pointer(Void).null
        creation_hash = Pointer(Void).null
        creation_ticket = Pointer(Void).null
        rc = LibTss.Esys_CreatePrimary(
          @esys_context, ESYS_TR_RH_OWNER,
          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
          pointerof(in_sensitive), pointerof(in_public),
          pointerof(outside_info), pointerof(creation_pcr),
          pointerof(handle),
          pointerof(out_public), pointerof(creation_data),
          pointerof(creation_hash), pointerof(creation_ticket),
        )
        check(rc, "Esys_CreatePrimary")
        LibTss.Esys_Free(out_public)
        LibTss.Esys_Free(creation_data)
        LibTss.Esys_Free(creation_hash)
        LibTss.Esys_Free(creation_ticket)
        handle
      end

      private def create_sealed(
        parent : UInt32,
        data_key : Bytes,
        out_private : Void**,
        out_public : Void**,
      ) : Nil
        in_sensitive = sealed_sensitive_create(data_key)
        in_public = keyedhash_template
        outside_info = LibTss::TPM2B_DATA.new
        creation_pcr = LibTss::TPML_PCR_SELECTION.new
        creation_data = Pointer(Void).null
        creation_hash = Pointer(Void).null
        creation_ticket = Pointer(Void).null
        rc = LibTss.Esys_Create(
          @esys_context, parent,
          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
          pointerof(in_sensitive), pointerof(in_public),
          pointerof(outside_info), pointerof(creation_pcr),
          out_private, out_public,
          pointerof(creation_data), pointerof(creation_hash), pointerof(creation_ticket),
        )
        # Scrub the copy of K embedded in the sensitive template regardless of RC.
        pointerof(in_sensitive).as(UInt8*).clear(sizeof(LibTss::TPM2B_SENSITIVE_CREATE))
        check(rc, "Esys_Create")
        LibTss.Esys_Free(creation_data)
        LibTss.Esys_Free(creation_hash)
        LibTss.Esys_Free(creation_ticket)
      end

      private def load_sealed(parent : UInt32, out_private : Void*, out_public : Void*) : UInt32
        handle = 0_u32
        rc = LibTss.Esys_Load(
          @esys_context, parent,
          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
          out_private, out_public, pointerof(handle),
        )
        check(rc, "Esys_Load")
        handle
      end

      # Empty TPM2B_SENSITIVE_CREATE: empty userAuth, empty data. `.new` zeroes
      # every field, which is exactly an all-empty sensitive.
      private def empty_sensitive_create : LibTss::TPM2B_SENSITIVE_CREATE
        LibTss::TPM2B_SENSITIVE_CREATE.new
      end

      # TPM2B_SENSITIVE_CREATE carrying `data_key` as the sealed data, with an
      # empty userAuth (so the object unseals under an empty-password session).
      private def sealed_sensitive_create(data_key : Bytes) : LibTss::TPM2B_SENSITIVE_CREATE
        sensitive = LibTss::TPM2B_SENSITIVE_CREATE.new
        sensitive.sensitive.data.size = data_key.size.to_u16
        buffer = StaticArray(UInt8, 128).new(0_u8)
        data_key.copy_to(buffer.to_unsafe, data_key.size)
        sensitive.sensitive.data.buffer = buffer
        # Scrub the stack copy of K; the caller scrubs the returned struct.
        buffer.to_unsafe.clear(buffer.size)
        sensitive
      end

      # RSA-2048, AES-128-CFB restricted decrypt (storage) parent template.
      private def rsa_storage_template : LibTss::TPM2B_PUBLIC
        public_key = LibTss::TPM2B_PUBLIC.new
        public_key.public_area.type = TPM2_ALG_RSA
        public_key.public_area.name_alg = TPM2_ALG_SHA256
        public_key.public_area.object_attributes = RSA_STORAGE_ATTRIBUTES
        public_key.public_area.parameters.rsa_detail.symmetric.algorithm = TPM2_ALG_AES
        public_key.public_area.parameters.rsa_detail.symmetric.key_bits = 128_u16
        public_key.public_area.parameters.rsa_detail.symmetric.mode = TPM2_ALG_CFB
        public_key.public_area.parameters.rsa_detail.scheme.scheme = TPM2_ALG_NULL
        public_key.public_area.parameters.rsa_detail.key_bits = 2048_u16
        public_key.public_area.parameters.rsa_detail.exponent = 0_u32
        public_key
      end

      # Keyedhash sealed-data object template (plain seal: scheme == NULL).
      private def keyedhash_template : LibTss::TPM2B_PUBLIC
        public_key = LibTss::TPM2B_PUBLIC.new
        public_key.public_area.type = TPM2_ALG_KEYEDHASH
        public_key.public_area.name_alg = TPM2_ALG_SHA256
        public_key.public_area.object_attributes = SEALED_DATA_ATTRIBUTES
        public_key.public_area.parameters.keyed_hash_detail.scheme.scheme = TPM2_ALG_NULL
        public_key
      end

      private def check(rc : UInt32, operation : String) : Nil
        return if rc == TSS2_RC_SUCCESS
        raise Error.new("#{operation} failed with TSS2_RC 0x#{rc.to_s(16)}")
      end
    end
  end
{% end %}
