using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using CommandLine;
using CommandLine.Text;

namespace SilverSAML;

public class Program
{
	public static void Main(string[] commandLine)
	{
		var arguments = new Parser()
			.ParseArguments<JsonFileOptions, SAMLConfigOptions>(commandLine);

		arguments
			.WithParsed<JsonFileOptions>(options => ProcessJson(options))
			.WithParsed<SAMLConfigOptions>(options => ProcessSAML(options))
			.WithNotParsed(error =>
			{
				var helpText = HelpText.AutoBuild(arguments,
					onError =>
					{
						onError.AdditionalNewLineAfterOption = false;
						return HelpText.DefaultParsingErrorsHandler(arguments, onError);
					},
					onExample => onExample
				);
				Console.Error.Write(helpText);
			});
	}

	static void ProcessJson(JsonFileOptions options)
	{
		var parsedArgs = ParseJsonAttributes(options.JsonFile);
		try
		{
			var pfxFilePath = parsedArgs["pfxPath"];
			var pfxPassword = parsedArgs["pfxPassword"];
			var identityProviderIdentifier = parsedArgs["idpid"];
			var recipient = parsedArgs["recipient"];
			var subjectNameID = parsedArgs["subjectnameid"];
			var audience = parsedArgs["audience"];
			var attributes = parsedArgs["attributes"].Split(',')
				.Select(pair => pair.Split('='))
				.ToDictionary(keyValue => keyValue[0], keyValue => keyValue[1]);

			var samlResponse = SAMLResponseGenerator.Generate(
				pfxFilePath,
				pfxPassword,
				identityProviderIdentifier,
				attributes,
				subjectNameID,
				recipient,
				audience
			);

			Console.WriteLine("Generated SAML response:");
			Console.WriteLine(samlResponse);
		}
		catch (KeyNotFoundException ex)
		{
			Console.Error.WriteLine("Missing required argument: {0}", ex.Message);
		}
	}

	static Dictionary<string, string> ParseJsonAttributes(string filePath)
	{
		var result = new Dictionary<string, string>();

		var attributes = JsonConvert.DeserializeObject<Dictionary<string, object>>(
			File.ReadAllText(filePath)
		);
		foreach (var attribute in attributes!)
		{
			if (attribute.Key == "attributes")
			{
				var attributeObject = (JObject)attribute.Value;

				var keyValuePairs = attributeObject.Properties()
					.Select(property => $"{property.Name}={property.Value}");

				result[attribute.Key] = string.Join(",", keyValuePairs);
			}
			else
			{
				result[attribute.Key] = attribute.Value.ToString()!;
			}
		}


		return result;
	}

	static void ProcessSAML(SAMLConfigOptions options)
	{
		Console.WriteLine(options);

		try
		{
			var attributes = options.Attributes.Split(',')
				.Select(pair => pair.Split('='))
				.ToDictionary(keyValue => keyValue[0], keyValue => keyValue[1]);

			var samlResponse = SAMLResponseGenerator.Generate(
				options.PfxPath, options.PfxPassword,
				options.IdentityProviderIdentifier, attributes,
				options.SubjectNameId, options.Recipient, options.Audience
			);

			Console.WriteLine("Generated SAML response:");
			Console.WriteLine(samlResponse);
		}
		catch (KeyNotFoundException ex)
		{
			Console.Error.WriteLine("Missing required argument: {0}", ex.Message);
		}
	}
}