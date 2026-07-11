# gRPC Security Testing

A GitHub-ready note series covering gRPC penetration testing methodology, from protocol fundamentals through authorization and injection testing. Companion series to the API Security Tooling and Microservices Security Testing note libraries.

## Scope

gRPC is increasingly common as the internal transport for microservices architectures, and is showing up more often as a direct client-facing protocol (mobile apps, gRPC-Web frontends). This series treats it as its own testing surface — the underlying vulnerability classes (BOLA, BFLA, injection) are the same ones covered elsewhere in this note library, but the transport (HTTP/2, binary protobuf) changes how you find, deliver, and detect them.

## Files

| File | Covers |
|---|---|
| [01-grpc-fundamentals.md](./01-grpc-fundamentals.md) | Protocol Buffers serialization mechanics, reading `.proto` files, gRPC vs REST, gRPC vs gRPC-Web, HTTP/2 transport essentials, how gRPC traffic appears in Burp |
| [02-service-reflection-enumeration.md](./02-service-reflection-enumeration.md) | Using gRPC server reflection to enumerate services, methods, and message schemas without a `.proto` file; fallback enumeration when reflection is disabled |
| [03-protobuf-manipulation-burp.md](./03-protobuf-manipulation-burp.md) | Intercepting, decoding, and editing protobuf messages in Burp Suite; schema mode vs blackbox mode; the edit-and-send workflow used throughout the rest of the series |
| [04-authorization-testing-bola-bfla.md](./04-authorization-testing-bola-bfla.md) | Applying BOLA and BFLA testing patterns to individual RPC methods; interpreting `grpc-status` codes for authorization results |
| [05-injection-testing.md](./05-injection-testing.md) | Delivering SQLi, OS command injection, and SSTI through decoded gRPC string fields; dedicated WAF/API Gateway detection and bypass section |
| [06-tooling-grpcurl-burp.md](./06-tooling-grpcurl-burp.md) | Full flag-by-flag `grpcurl` reference; Burp gRPC/protobuf plugin landscape, installation, and setup |
| [07-cheatsheet.md](./07-cheatsheet.md) | Consolidated quick reference: workflow checklist, status codes, payload lists, practice environment mapping |

## Recommended reading order

Sequential, 01 → 07. Each file assumes the mechanisms covered in earlier files rather than re-explaining them — fundamentals and reflection (01–02) are prerequisites for everything else, protobuf manipulation (03) is the mechanical workflow that authorization and injection testing (04–05) both build on, and tooling (06) is referenced throughout rather than read as a standalone piece.

## WAF / API Gateway coverage

Addressed per topic rather than as a single bolted-on section, since relevance differs sharply by activity. Reflection and enumeration are authorization concerns, not signature-evasion ones. Injection testing is where this matters substantially — see file 05, section 6 for detection methodology and bypass considerations specific to gRPC's binary transport. Full breakdown of relevance (or explicit non-relevance) per file is in file 01, section 9.

## Practice environments

PortSwigger Web Security Academy has no dedicated gRPC lab category at the time of writing — this series notes that explicitly rather than forcing a lab mapping that doesn't exist. See file 07, section 6 for what does transfer conceptually (API/GraphQL labs), plus HackTheBox and TryHackMe as supplementary gRPC-specific practice, and a suggestion for self-hosting a test target.

## Conventions

- Mechanism-first explanations — how the protocol/tool actually works before how to attack it.
- Every `grpcurl` command and Burp workflow step is broken down flag by flag / step by step.
- WAF/API Gateway relevance addressed explicitly per topic, including explicit non-applicability where relevant.
- Cross-references to sibling series (API Security Tooling, Microservices Security Testing, web application injection series) rather than duplicating shared content.
- Full English only.

## Author

4xpl0it Security — Rasel Hossain (CTO / Lead Pentester)
