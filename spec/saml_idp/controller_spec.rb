# encoding: utf-8
require 'spec_helper'

describe SamlIdp::Controller do
  include SamlIdp::Controller

  def params
    @params ||= {}
  end

  it "should find the SAML ACS URL when set via a preceding SAML Request" do
    requested_saml_acs_url = "https://example.com/saml/consume"
    params[:SAMLRequest] = make_saml_request(requested_saml_acs_url)
    validate_saml_request
    saml_acs_url.should == requested_saml_acs_url
  end

  it "should find the SAML ACS URL when set via a parameter" do
    requested_acs_url = "https://serviceprovicer.org/acs/login"
    params[:saml_acs_url] = requested_acs_url
    saml_acs_url.should == requested_acs_url
  end

  it "should create a SAMLResponse without InResponseTo attributes" do
    # when there is no preceding saml_request to set the RequestID, the Response and SubjectConfirmationData
    # elements should NOT contain an InResponseTo attribute
    requested_acs_url = "https://serviceprovicer.org/acs/login"
    params[:saml_acs_url] = requested_acs_url
    saml_response = encode_SAMLResponse("foo@bar.com", issuer_uri: "http://someissuer.org")
    response = Onelogin::Saml::Response.new(saml_response)
    response.name_id.should == "foo@bar.com"
    response.issuer.should == "http://someissuer.org"
    response.settings = saml_settings
    response.is_valid?.should be_true
    response.attributes.should be_empty
    doc = REXML::Document.new(Base64.decode64(response.response))
    doc.root.attributes["InResponseTo"].should be_nil
    doc.root.attributes["Destination"].should == requested_acs_url
  end

  context "SAML Responses" do
    before(:each) do
      params[:SAMLRequest] = make_saml_request
      validate_saml_request
    end

    it "should create a SAML Response without attributes" do
      saml_response = encode_SAMLResponse("foo@example.com")
      response = Onelogin::Saml::Response.new(saml_response)
      response.name_id.should == "foo@example.com"
      response.issuer.should == "http://example.com"
      response.settings = saml_settings
      response.is_valid?.should be_true
      response.attributes.should be_empty
      doc = REXML::Document.new(Base64.decode64(response.response))
      doc.root.attributes["InResponseTo"].should == @saml_request_id
      doc.root.attributes["Destination"].should == "https://foo.example.com/saml/consume"
    end

    it "should create a SAML Response with Attributes" do
      saml_response = encode_SAMLResponse("foo@example.com", attributes: {
          companyID: "Corporation X", firstName: "John", lastName: "Doe", userId: "123456789"
      })
      response = Onelogin::Saml::Response.new(saml_response)
      response.name_id.should == "foo@example.com"
      response.issuer.should == "http://example.com"
      response.settings = saml_settings
      response.is_valid?.should be_true
      puts response
      response.attributes[:companyID].should == "Corporation X"
      response.attributes[:firstName].should == "John"
      response.attributes[:lastName].should == "Doe"
      response.attributes[:userId].should == "123456789"
      doc = REXML::Document.new(Base64.decode64(response.response))
      doc.root.attributes["InResponseTo"].should == @saml_request_id
      doc.root.attributes["Destination"].should == "https://foo.example.com/saml/consume"
    end

    it "should create a SAML Response with custom Audience" do
      expected_audience = "http://some.audience.com"
      saml_response = encode_SAMLResponse("foo@example.com", audience_uri: expected_audience)
      response = Onelogin::Saml::Response.new(saml_response)
      response.settings = saml_settings
      response.is_valid?.should be_true
      doc = REXML::Document.new(Base64.decode64(response.response))
      found_audience = doc.root.elements["//Assertion//Conditions//AudienceRestriction//Audience"].children[0]
      found_audience.should == expected_audience
    end

    [:sha1, :sha256].each do |algorithm_name|
      it "should create a SAML Response using the #{algorithm_name} algorithm" do
        self.algorithm = algorithm_name
        saml_response = encode_SAMLResponse("foo@example.com")
        response = Onelogin::Saml::Response.new(saml_response)
        response.name_id.should == "foo@example.com"
        response.issuer.should == "http://example.com"
        response.settings = saml_settings
        response.is_valid?.should be_true
      end
    end

    [:sha384, :sha512].each do |algorithm_name|
      it "should create a SAML Response using the #{algorithm_name} algorithm" do
        pending "release of ruby-saml v0.5.4" do
          self.algorithm = algorithm_name
          saml_response = encode_SAMLResponse("foo@example.com")
          response = Onelogin::Saml::Response.new(saml_response)
          response.name_id.should == "foo@example.com"
          response.issuer.should == "http://example.com"
          response.settings = saml_settings
          response.is_valid?.should be_true
        end
      end
    end
  end

end