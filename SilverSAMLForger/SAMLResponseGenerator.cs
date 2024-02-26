using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Text;
using System.Web;
using System.Text.RegularExpressions;

namespace SilverSAML;

public class SAMLResponseGenerator
{
	public static string Generate(
		string pfxFilePath,
		string pfxPassword,
		string identityProviderIdentifier,
		Dictionary<string, string> attributes,
		string subjectNameID,
		string recipient,
		string audience
	)
	{
		try
		{
			var document = new XmlDocument();

			// Create SAML Response element
			var response = document.CreateElement("samlp", "Response", "urn:oasis:names:tc:SAML:2.0:protocol");
			response.SetAttribute("ID", $"_{Guid.NewGuid()}");
			response.SetAttribute("Version", "2.0");
			response.SetAttribute("IssueInstant", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
			response.SetAttribute("Destination", recipient);
			document.AppendChild(response);

			var issuer = document.CreateElement("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
			issuer.InnerText = identityProviderIdentifier;
			response.AppendChild(issuer);

			var status = document.CreateElement("samlp", "Status", "urn:oasis:names:tc:SAML:2.0:protocol");
			response.AppendChild(status);

			var statusCode = document.CreateElement("samlp", "StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol");
			statusCode.SetAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
			status.AppendChild(statusCode);

			var assertion = document.CreateElement("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion");
			assertion.SetAttribute("ID", "_" + Guid.NewGuid().ToString());
			assertion.SetAttribute("Version", "2.0");
			assertion.SetAttribute("IssueInstant", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));

			var subject = document.CreateElement("Subject", "urn:oasis:names:tc:SAML:2.0:assertion");
			assertion.AppendChild(subject);

			var newIssuer = document.CreateElement("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
			newIssuer.InnerText = identityProviderIdentifier;
			assertion.AppendChild(newIssuer);

			var nameId = document.CreateElement("NameID", "urn:oasis:names:tc:SAML:2.0:assertion");
			nameId.SetAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
			nameId.InnerText = subjectNameID;
			subject.AppendChild(nameId);

			var subjectConfirmation = document.CreateElement("SubjectConfirmation", "urn:oasis:names:tc:SAML:2.0:assertion");
			subjectConfirmation.SetAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");

			var subjectConfirmationData = document.CreateElement("SubjectConfirmationData", "urn:oasis:names:tc:SAML:2.0:assertion");
			subjectConfirmationData.SetAttribute("NotOnOrAfter", DateTime.UtcNow.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
			subjectConfirmationData.SetAttribute("Recipient", recipient);
			subjectConfirmation.AppendChild(subjectConfirmationData);
			subject.AppendChild(subjectConfirmation);

			var conditions = document.CreateElement("Conditions", "urn:oasis:names:tc:SAML:2.0:assertion");
			conditions.SetAttribute("NotBefore", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
			conditions.SetAttribute("NotOnOrAfter", DateTime.UtcNow.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
			assertion.AppendChild(conditions);

			var audienceRestriction = document.CreateElement("AudienceRestriction", "urn:oasis:names:tc:SAML:2.0:assertion");
			conditions.AppendChild(audienceRestriction);

			var audienceElement = document.CreateElement("Audience", "urn:oasis:names:tc:SAML:2.0:assertion");
			audienceElement.InnerText = audience;
			audienceRestriction.AppendChild(audienceElement);
			response.AppendChild(assertion);

			var attributeStatement = document.CreateElement("AttributeStatement", "urn:oasis:names:tc:SAML:2.0:assertion");
			assertion.AppendChild(attributeStatement);

			foreach (var attribute in attributes)
			{ 
				var attributeElement = document.CreateElement("Attribute", "urn:oasis:names:tc:SAML:2.0:assertion");
				attributeElement.SetAttribute("Name", attribute.Key);
				attributeStatement.AppendChild(attributeElement);

				var attributeValueElement = document.CreateElement("AttributeValue", "urn:oasis:names:tc:SAML:2.0:assertion");
				attributeValueElement.InnerText = attribute.Value;
				attributeElement.AppendChild(attributeValueElement);
			}

			// Sign the response
			var authnStatement = document.CreateElement("AuthnStatement", "urn:oasis:names:tc:SAML:2.0:assertion");
			authnStatement.SetAttribute("AuthnInstant", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
			authnStatement.SetAttribute("SessionIndex", "_" + Guid.NewGuid().ToString());

			var authContext = document.CreateElement("AuthnContext", "urn:oasis:names:tc:SAML:2.0:assertion");
			var authnContextClassRef = document.CreateElement("AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
			authnContextClassRef.InnerText = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
			authContext.AppendChild(authnContextClassRef);
			authnStatement.AppendChild(authContext);
			assertion.AppendChild(authnStatement);

			var signedXml = new SignedXml(document);
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			var certificate = new X509Certificate2(pfxFilePath, pfxPassword);
			signedXml.SigningKey = certificate.PrivateKey;

			// Retrieve the value of the "ID" attribute on the assertion element.
			var reference = new Reference("#" + assertion.Attributes["ID"].Value);
			reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			reference.AddTransform(new XmlDsigExcC14NTransform());

			signedXml.AddReference(reference);

			// Include the public key of the certificate in the assertion.
			signedXml.KeyInfo = new KeyInfo();
			signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certificate, X509IncludeOption.EndCertOnly));

			signedXml.ComputeSignature();
			assertion.InsertAfter(signedXml.GetXml(), assertion.FirstChild);

			var xmlBytes = Encoding.UTF8.GetBytes(document.OuterXml);
			var encodedResponse = Convert.ToBase64String(xmlBytes);
			var urlEncodedResponse = HttpUtility.UrlEncode(encodedResponse);
			var SAMLResponse = Regex.Replace(urlEncodedResponse, @"%[a-f\d]{2}", m => m.Value.ToUpper());

			return SAMLResponse;
		}
		catch (Exception ex)
		{
			throw new Exception("Failed to generate SAML response", ex);
		}
	}
}

