require "./item"

module PlaywrightSecureMcp
  # Resolves a caller-supplied field name to a concrete Field within a cached
  # item. Preference: purpose match (for username/password), then a field with
  # a value over one without.
  class FieldSelector
    class NotFoundError < Exception
    end

    PURPOSES = {"username" => "USERNAME", "password" => "PASSWORD"}

    def select(item : Item, field : String) : Field
      purpose = PURPOSES[field]?
      candidates = item.fields.each_value.select do |candidate|
        matches?(candidate, name: field, purpose: purpose)
      end.to_a
      best = candidates.max_by? { |candidate| rank(candidate, purpose: purpose) }
      raise NotFoundError.new("no field #{field.inspect} on item") if best.nil?
      best
    end

    private def matches?(candidate : Field, *, name : String, purpose : String?) : Bool
      candidate.id == name || candidate.label == name ||
        (!purpose.nil? && candidate.purpose == purpose)
    end

    private def rank(candidate : Field, *, purpose : String?) : Tuple(Int32, Int32)
      purpose_match = !purpose.nil? && candidate.purpose == purpose
      {purpose_match ? 1 : 0, candidate.value.nil? ? 0 : 1}
    end
  end
end
