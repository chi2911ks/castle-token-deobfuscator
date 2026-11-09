from sursolver import SurSolver, TaskType

API_KEY = "sur_DXWQ8d1bvTbZPuFN8ApgjuBSmDlxYR7a1DIqgIzGPgLnqNHy"

client = SurSolver(API_KEY)

result = client.solve(
    {
        "type": TaskType.CastleWebToken,
        "type": "CastleWebToken",
        "websiteURL": "https://x.com/login",
        "websiteKey": "pk_AvRa79bHyJSYSQHnRpcVtzyxetSvFerx",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
  
    }
)
print(result.solution["token"])