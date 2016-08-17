module Mail
  module VERSION

    MAJOR = 2
    MINOR = 6
    PATCH = 3
    BFY_PATCH = 2

    STRING = [MAJOR, MINOR, PATCH, BFY_PATCH].compact.join('.')

    def self.version
      STRING
    end

  end
end
