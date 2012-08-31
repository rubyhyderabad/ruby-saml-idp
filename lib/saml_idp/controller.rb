# encoding: utf-8
module SamlIdp
  module Controller

    require 'openssl'
    require 'base64'
    require 'time'
    require 'uuid'

    attr_accessor :x509_certificate, :secret_key, :algorithm
    attr_accessor :saml_acs_url

    def x509_certificate
      return @x509_certificate if defined?(@x509_certificate)
      @x509_certificate = SamlIdp.config.x509_certificate
    end

    def secret_key
      return @secret_key if defined?(@secret_key)
      @secret_key = SamlIdp.config.secret_key
    end

    def algorithm
      return @algorithm if defined?(@algorithm)
      self.algorithm = SamlIdp.config.algorithm
      @algorithm
    end

    def algorithm=(algorithm)
      @algorithm = algorithm
      if algorithm.is_a?(Symbol)
        @algorithm = case algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        else
          OpenSSL::Digest::SHA1
        end
      end
      @algorithm
    end

    def algorithm_name
      algorithm.to_s.split('::').last.downcase
    end

    def saml_acs_url
      @saml_acs_url ||= params[:saml_acs_url]
    end

    protected

      def validate_saml_request(saml_request = params[:SAMLRequest])
        decode_SAMLRequest(saml_request)
      end

      def decode_SAMLRequest(saml_request)
        zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        @saml_request = zstream.inflate(Base64.decode64(saml_request))
        zstream.finish
        zstream.close
        @saml_request_id = @saml_request[/ID=['"](.+?)['"]/, 1]
        @saml_acs_url = @saml_request[/AssertionConsumerServiceURL=['"](.+?)['"]/, 1]
      end

      def encode_SAMLResponse(nameID, opts = {})
        response_id, assertion_id = UUID.generate, UUID.generate
        issuer_uri = opts[:issuer_uri] || default_issuer
        assertion = build_assertion(nameID, assertion_id, opts)
        digest_value = Base64.encode64(algorithm.digest(assertion)).gsub(/\n/, '')
        signed_info = build_signed_info(assertion_id, digest_value)
        signature_value = sign(signed_info).gsub(/\n/, '')
        signature = build_signature(signed_info, signature_value)
        assertion_and_signature = insert_signature(assertion, signature)
        xml = build_response(response_id, issuer_uri, assertion_and_signature)
        Base64.encode64(xml)
      end

    private

      def sign(data)
        key = OpenSSL::PKey::RSA.new(self.secret_key)
        Base64.encode64(key.sign(algorithm.new, data))
      end

      def build_response(response_id, issuer_uri, assertion_and_signature)
        now = Time.now.utc

        # Include an InResponseTo attribute if there is a request ID.
        if @saml_request_id
          %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{saml_acs_url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="#{@saml_request_id}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]
        else
          %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{saml_acs_url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]
        end
      end

      def build_assertion(name_id, assertion_id, opts = {})
        now = Time.now.utc

        issuer_uri = opts[:issuer_uri] || default_issuer
        audience_uri = opts[:audience_uri] || default_audience
        authn_context_class_ref = opts[:authn_context_class_ref] || SamlIdp::Default::AUTHN_CONTEXT_CLASS_REF

        attributes = opts[:attributes] ? opts[:attributes].map { |name, value|
          %[<Attribute Name="#{name}"><AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">#{value}</AttributeValue></Attribute>]
        }.join : ""

        %[<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{assertion_id}" IssueInstant="#{now.iso8601}" Version="2.0"><Issuer>#{issuer_uri}</Issuer>#{build_subject(name_id, opts)}<Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><AudienceRestriction><Audience>#{audience_uri}</Audience></AudienceRestriction></Conditions><AttributeStatement>#{attributes}</AttributeStatement><AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{assertion_id}"><AuthnContext><AuthnContextClassRef>#{authn_context_class_ref}</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>]
      end

      def build_subject(name_id, opts = {})
        name_id_format = opts[:name_id_format] || SamlIdp::Default::NAME_ID_FORMAT

        %[<Subject><NameID Format="#{name_id_format}">#{name_id}</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">#{build_subject_confirmation_data}</SubjectConfirmation></Subject>]
      end

      def build_subject_confirmation_data
        now = Time.now.utc
        if @saml_request_id
          # Include an InResponseTo attribute if there is a request ID.
          %[<SubjectConfirmationData InResponseTo="#{@saml_request_id}" NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{saml_acs_url}"></SubjectConfirmationData>]
        else
          %[<SubjectConfirmationData NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{saml_acs_url}"></SubjectConfirmationData>]
        end
      end

      def build_signed_info(assertion_id, digest_value)
        %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod><ds:Reference URI="#_#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]
      end

      def build_signature(signed_info, signature_value)
        %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature>]
      end

      def insert_signature(assertion, signature)
        assertion.sub(/Issuer\>\<Subject/, "Issuer>#{signature}<Subject")
      end

      def default_issuer
        (defined?(request) && request.url) || "http://example.com"
      end

      def default_audience
        (defined?(saml_acs_url) && (saml_acs_url[/^(.*?\/\/.*?\/)/, 1])) || "http://example.audience.com"
      end

  end
end