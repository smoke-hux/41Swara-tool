# Smart Contract Scanner API Architecture

## System Architecture Overview

The current system is a CLI-based vulnerability scanner with these core components:

1. **Scanner Module** (`scanner.rs`) - Core scanning engine
2. **Parser Module** (`parser.rs`) - Solidity code parsing
3. **Vulnerabilities Module** (`vulnerabilities.rs`) - Vulnerability detection rules
4. **Reporter Modules** (`reporter.rs`, `professional_reporter.rs`) - Output formatting

## Recommended API Architecture

### 1. API Layer Structure

```
src/
├── main.rs (CLI entry point)
├── api/
│   ├── mod.rs
│   ├── server.rs (API server setup)
│   ├── handlers.rs (endpoint handlers)
│   ├── models.rs (request/response models)
│   └── middleware.rs (auth, CORS, logging)
├── scanner.rs (existing)
├── vulnerabilities.rs (existing)
└── ...
```

### 2. Core API Endpoints Design

#### File Scanning Endpoints

- `POST /api/v1/scan` - Scan contract code directly
- `POST /api/v1/scan/file` - Upload and scan .sol file
- `POST /api/v1/scan/batch` - Scan multiple contracts

#### Report Generation Endpoints

- `POST /api/v1/report/json` - Get JSON vulnerability report
- `POST /api/v1/report/audit` - Generate professional audit report
- `GET /api/v1/report/{scan_id}` - Retrieve previous scan results

#### Utility Endpoints

- `GET /api/v1/health` - Service health check
- `GET /api/v1/vulnerabilities/catalog` - List all detectable vulnerabilities
- `GET /api/v1/stats` - Scanning statistics

### 3. Data Flow Architecture

```
Frontend Request → API Handler → Validation → Scanner Service → Response
                                      ↓
                              ContractScanner
                                      ↓
                          Vulnerability Detection
                                      ↓
                              Report Generation
```

### 4. Request/Response Models

#### Scan Request

```json
{
  "content": "pragma solidity ^0.8.0;...",
  "filename": "Contract.sol",
  "options": {
    "verbose": true,
    "format": "json"
  }
}
```

#### Scan Response

```json
{
  "scan_id": "uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "file": "Contract.sol",
  "vulnerabilities": [
    {
      "severity": "Critical",
      "category": "Reentrancy",
      "line_number": 42,
      "title": "Potential Reentrancy Attack",
      "description": "...",
      "recommendation": "..."
    }
  ],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2
  }
}
```

#### Batch Scan Request

```json
{
  "files": [
    {
      "filename": "Contract1.sol",
      "content": "pragma solidity ^0.8.0;..."
    },
    {
      "filename": "Contract2.sol",
      "content": "pragma solidity ^0.8.0;..."
    }
  ],
  "options": {
    "verbose": false,
    "format": "json"
  }
}
```

#### Audit Report Request

```json
{
  "content": "pragma solidity ^0.8.0;...",
  "filename": "Contract.sol",
  "project_name": "DeFi Protocol",
  "sponsor": "Example Corp",
  "auditor": "41Swara Security Team"
}
```

#### Vulnerability Catalog Response

```json
{
  "categories": [
    {
      "name": "Reentrancy",
      "severity_levels": ["Critical", "High"],
      "description": "Vulnerabilities related to reentrancy attacks"
    },
    {
      "name": "AccessControl",
      "severity_levels": ["Critical", "High", "Medium"],
      "description": "Access control and permission issues"
    }
  ]
}
```

### 5. Technology Stack Options

#### Option A: Actix-Web (Recommended)
- High performance, actor-based
- Built-in WebSocket support
- Excellent async support

**Dependencies:**
```toml
actix-web = "4.4"
actix-cors = "0.6"
tokio = { version = "1", features = ["full"] }
env_logger = "0.10"
uuid = { version = "1.0", features = ["v4"] }
```

#### Option B: Rocket
- Type-safe, macro-based routing
- Simpler syntax
- Good for rapid development

#### Option C: Axum
- Tower middleware ecosystem
- Lightweight and modular
- Good tokio integration

### 6. Additional Components to Consider

#### Authentication/Authorization
- API key authentication
- JWT tokens for session management
- Rate limiting per API key

#### Storage Layer (Optional)
- PostgreSQL/SQLite for scan history
- Redis for caching scan results
- File storage for uploaded contracts

#### Background Processing
- Queue system for large batch scans
- WebSocket for real-time scan progress
- Scheduled vulnerability database updates

### 7. Deployment Architecture

```
Load Balancer
     ↓
API Servers (multiple instances)
     ↓
Database (if persisting results)
     ↓
Cache Layer (Redis)
```

### 8. Frontend Integration Points

The frontend will need to:

1. Upload files or paste contract code
2. Display vulnerability results with syntax highlighting
3. Filter/sort vulnerabilities by severity
4. Export reports in various formats
5. Show scan history (if implemented)
6. Display real-time scanning progress

The API should support:

- CORS for browser-based frontends
- Multipart form uploads
- JSON request/response format
- Pagination for large results
- Error handling with proper HTTP status codes

### 9. Error Handling

#### Standard Error Response Format

```json
{
  "error": {
    "code": "INVALID_CONTRACT",
    "message": "The provided Solidity contract contains syntax errors",
    "details": {
      "line": 15,
      "column": 8,
      "syntax_error": "Unexpected token ';'"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Common Error Codes

- `INVALID_CONTRACT` - Malformed Solidity code
- `UNSUPPORTED_VERSION` - Unsupported Solidity version
- `FILE_TOO_LARGE` - Uploaded file exceeds size limit
- `RATE_LIMIT_EXCEEDED` - Too many requests
- `INTERNAL_ERROR` - Server-side processing error

### 10. Security Considerations

1. **Input Validation**: Sanitize all contract code inputs
2. **File Size Limits**: Restrict upload file sizes
3. **Rate Limiting**: Prevent API abuse
4. **CORS Configuration**: Restrict origins in production
5. **Logging**: Log all scan requests for security monitoring
6. **Sandboxing**: Ensure contract parsing is isolated

### 11. Performance Considerations

1. **Async Processing**: Use async/await for all I/O operations
2. **Connection Pooling**: If using database storage
3. **Caching**: Cache vulnerability rules and common scan results
4. **Streaming**: Stream large responses to reduce memory usage
5. **Pagination**: Paginate large result sets

### 12. Monitoring and Observability

1. **Health Checks**: Implement comprehensive health endpoints
2. **Metrics**: Track scan duration, error rates, and throughput
3. **Logging**: Structured logging with correlation IDs
4. **Alerts**: Set up alerts for high error rates or slow responses

This architecture provides a solid foundation for building a scalable, maintainable API that exposes all the functionality of your smart contract scanner while maintaining clean separation of concerns and supporting future enhancements.