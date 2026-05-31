## Backend PR Style Checklist

Use this checklist for any backend PR touching `service-api`.

- [ ] Imports are grouped and ordered by the project rule.
- [ ] Handlers use consistent error flow (`sendErrorResponse/sendResponse` + blank line + `return`).
- [ ] Request payloads are decoded through `decodeBody(...)` where applicable.
- [ ] DTO requests use `validate` tags and `IsValid()` instead of ad-hoc empty checks.
- [ ] Backend handlers/DTOs do not trim/normalize user payload strings.
- [ ] `golangci-lint run ./...` passes locally.
