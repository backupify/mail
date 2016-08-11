require 'mail/fields'

# encoding: utf-8
module Mail
  # Provides a single class to call to create a new structured or unstructured
  # field.  Works out per RFC what field of field it is being given and returns
  # the correct field of class back on new.
  #
  # ===Per RFC 2822
  #
  #  2.2. Header Fields
  #
  #     Header fields are lines composed of a field name, followed by a colon
  #     (":"), followed by a field body, and terminated by CRLF.  A field
  #     name MUST be composed of printable US-ASCII characters (i.e.,
  #     characters that have values between 33 and 126, inclusive), except
  #     colon.  A field body may be composed of any US-ASCII characters,
  #     except for CR and LF.  However, a field body may contain CRLF when
  #     used in header "folding" and  "unfolding" as described in section
  #     2.2.3.  All field bodies MUST conform to the syntax described in
  #     sections 3 and 4 of this standard.
  #
  class Field

    include Utilities
    include Comparable

    STRUCTURED_FIELDS = %w[ bcc cc content-description content-disposition
                            content-id content-location content-transfer-encoding
                            content-type date from in-reply-to keywords message-id
                            mime-version received references reply-to
                            resent-bcc resent-cc resent-date resent-from
                            resent-message-id resent-sender resent-to
                            return-path sender to ]

    KNOWN_FIELDS = STRUCTURED_FIELDS + ['comments', 'subject']

    FIELDS_MAP = {
      "to" => ToField,
      "cc" => CcField,
      "bcc" => BccField,
      "message-id" => MessageIdField,
      "in-reply-to" => InReplyToField,
      "references" => ReferencesField,
      "subject" => SubjectField,
      "comments" => CommentsField,
      "keywords" => KeywordsField,
      "date" => DateField,
      "from" => FromField,
      "sender" => SenderField,
      "reply-to" => ReplyToField,
      "resent-date" => ResentDateField,
      "resent-from" => ResentFromField,
      "resent-sender" =>  ResentSenderField,
      "resent-to" => ResentToField,
      "resent-cc" => ResentCcField,
      "resent-bcc" => ResentBccField,
      "resent-message-id" => ResentMessageIdField,
      "return-path" => ReturnPathField,
      "received" => ReceivedField,
      "mime-version" => MimeVersionField,
      "content-transfer-encoding" => ContentTransferEncodingField,
      "content-description" => ContentDescriptionField,
      "content-disposition" => ContentDispositionField,
      "content-type" => ContentTypeField,
      "content-id" => ContentIdField,
      "content-location" => ContentLocationField,
    }

    FIELD_NAME_MAP = FIELDS_MAP.inject({}) do |map, (field, field_klass)|
      map.update(field => field_klass::CAPITALIZED_FIELD)
    end

    # Generic Field Exception
    class FieldError < StandardError
    end

    # Raised when a parsing error has occurred (ie, a StructuredField has tried
    # to parse a field that is invalid or improperly written)
    class ParseError < FieldError #:nodoc:
      attr_accessor :element, :value, :reason

      def initialize(element, value, reason)
        @element = element
        @value = value
        @reason = reason
        super("#{element} can not parse |#{value}|\nReason was: #{reason}")
      end
    end

    # Raised when attempting to set a structured field's contents to an invalid syntax
    class SyntaxError < FieldError #:nodoc:
    end

    # Accepts a string:
    #
    #  Field.new("field-name: field data")
    #
    # Or name, value pair:
    #
    #  Field.new("field-name", "value")
    #
    # Or a name by itself:
    #
    #  Field.new("field-name")
    #
    # Note, does not want a terminating carriage return.  Returns
    # self appropriately parsed.  If value is not a string, then
    # it will be passed through as is, for example, content-type
    # field can accept an array with the type and a hash of
    # parameters:
    #
    #  Field.new('content-type', ['text', 'plain', {:charset => 'UTF-8'}])
    def initialize(name, value = nil, charset = 'utf-8')
      case
      when name.index(COLON)            # Field.new("field-name: field data")
        @charset = value.blank? ? charset : value
        @name = name[FIELD_PREFIX]
        @raw_value = name
        @value = nil
      when value.blank?                 # Field.new("field-name")
        @name = name
        @value = nil
        @raw_value = nil
        @charset = charset
      else                              # Field.new("field-name", "value")
        @name = name
        @value = value
        @raw_value = nil
        @charset = charset
      end
      @name = FIELD_NAME_MAP[@name.to_s.downcase] || @name
    end

    def field=(value)
      @field = value
    end

    def field
      _, @value = split(@raw_value) if @raw_value && !@value
      @field ||= create_field(@name, @value, @charset)
    end

    def name
      @name
    end

    def value
      field.value
    end

    def value=(val)
      @field = create_field(name, val, @charset)
    end

    def to_s
      field.to_s
    end

    def inspect
      "#<#{self.class.name} 0x#{(object_id * 2).to_s(16)} #{instance_variables.map do |ivar|
        "#{ivar}=#{instance_variable_get(ivar).inspect}"
      end.join(" ")}>"
    end

    def update(name, value)
      @field = create_field(name, value, @charset)
    end

    def same( other )
      match_to_s(other.name, self.name)
    end

    def responsible_for?( val )
      name.to_s.casecmp(val.to_s) == 0
    end

    alias_method :==, :same

    def <=>( other )
      self.field_order_id <=> other.field_order_id
    end

    def field_order_id
      @field_order_id ||= (FIELD_ORDER_LOOKUP[self.name.to_s.downcase] || 100)
    end

    def method_missing(name, *args, &block)
      field.send(name, *args, &block)
    end

    FIELD_ORDER = %w[ return-path received
                      resent-date resent-from resent-sender resent-to
                      resent-cc resent-bcc resent-message-id
                      date from sender reply-to to cc bcc
                      message-id in-reply-to references
                      subject comments keywords
                      mime-version content-type content-transfer-encoding
                      content-location content-disposition content-description ]

    FIELD_ORDER_LOOKUP = Hash[FIELD_ORDER.each_with_index.to_a]

    private

    def self.detector
      @char_detector ||= CharlockHolmes::EncodingDetector.new
    end

    # If the string is already of the same encoding, no encoding will take place; double-encoding forces a conversion
    def double_encode(str, opts = {})
      str.encode(Encoding::UTF_16LE, opts).encode(Encoding::UTF_8, opts)
    end

    def string_is_valid?(str)
      begin
        double_encode(str)
        true
      rescue Encoding::InvalidByteSequenceError, Encoding::UndefinedConversionError => e
        false
      end
    end

    def process_unsafe_string(raw_field)
      encoding = self.class.detector.detect(raw_field).try(:[], :encoding) || Encoding::UTF_8

      double_encode(raw_field.force_encoding(encoding), invalid: :replace, undef: :replace, replace: '_')
    end

    def process_content_disposition(raw_field)
      return raw_field unless raw_field.start_with?('Content-Disposition') && raw_field.include?('filename=')

      # Might want to check ascii_only?
      return raw_field if string_is_valid?(raw_field)

      header_parts = raw_field.split('filename=')
      filename = header_parts[1]
      filename = process_unsafe_string(filename).strip[1..-2]
      [header_parts.first, "filename*=", Mail::Encodings.param_encode(filename),].encode!(Encoding::ASCII)
      # [header_parts[0], "filename*=UTF-8''", ERB::Util.url_encode(filename),].join.encode!(Encoding::ASCII)
    end

    def process_content_type(raw_field)
      return raw_field unless raw_field.start_with?('Content-Type') && raw_field.include?('name=')

      return raw_field if string_is_valid?(raw_field)

      header_parts = raw_field.split(';').map { |s| s.strip }

      header_parts.each_with_index do |part, idx|
        key = part.split('=').first.strip

        next unless %w(filename name).include?(key)

        raw_filename = part.sub(/^\s*(file)?name\s*=\s*/, '')

        filename = process_unsafe_string(raw_filename).gsub(/(^"|"$)/, '')

        encoded_filename = Mail::Encodings.b_value_encode(filename)

        header_parts[idx] = "#{key}=\"#{encoded_filename}\""
      end

      header_parts.join('; ')
    end

    def split(raw_field)
      raw_field = process_content_disposition(raw_field)

      raw_field = process_content_type(raw_field)

      match_data = raw_field.mb_chars.match(FIELD_SPLIT)
      [match_data[1].to_s.mb_chars.strip, match_data[2].to_s.mb_chars.strip.to_s]
    rescue
      STDERR.puts "WARNING: Could not parse (and so ignoring) '#{raw_field}'"
    end

    # 2.2.3. Long Header Fields
    #
    #  The process of moving from this folded multiple-line representation
    #  of a header field to its single line representation is called
    #  "unfolding". Unfolding is accomplished by simply removing any CRLF
    #  that is immediately followed by WSP.  Each header field should be
    #  treated in its unfolded form for further syntactic and semantic
    #  evaluation.
    def unfold(string)
      string.gsub(/[\r\n \t]+/m, ' ')
    end

    def create_field(name, value, charset)
      value = unfold(value) if value.is_a?(String)

      begin
        new_field(name, value, charset)
      rescue Mail::Field::ParseError => e
        field = Mail::UnstructuredField.new(name, value)
        field.errors << [name, value, e]
        field
      end
    end

    def new_field(name, value, charset)
      lower_case_name = name.to_s.downcase
      if field_klass = FIELDS_MAP[lower_case_name]
        field_klass.new(value, charset)
      else
        OptionalField.new(name, value, charset)
      end
    end

  end

end
