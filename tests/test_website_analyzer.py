from src.website_analyzer import analyze_website_url


# Test URL
test_url = "http://secure-login-example.com/verify/account"


result = analyze_website_url(test_url)


print("=" * 50)
print("WEBSITE PHISHING ANALYZER")
print("=" * 50)

print("\nURL:")
print(result["url"])

print("\nDomain:")
print(result["domain"])

print("\nSubdomain:")
print(result["subdomain"])

print("\nProtocol:")
print(result["protocol"])

print("\nRisk Score:")
print(f"{result['score']}/100")

print("\nRisk Level:")
print(result["risk_level"])

print("\nFindings:")

if result["findings"]:

    for finding in result["findings"]:
        print("-", finding)

else:

    print("No suspicious characteristics detected.")