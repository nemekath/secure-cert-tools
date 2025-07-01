# Architecture and Software Stack

This document describes the hierarchical architecture, software stack, and design principles of the Secure Cert-Tools application.

## Table of Contents

1. [System Architecture Overview](#system-architecture-overview)
2. [Software Stack](#software-stack)
3. [Layer Architecture](#layer-architecture)
4. [Component Interactions](#component-interactions)
5. [Design Principles](#design-principles)
6. [Security Architecture](#security-architecture)
7. [Deployment Models](#deployment-models)

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│  Web Browser │ API Client │ curl/wget │ Mobile App │ Scripts    │
└─────────────────────────────────────────────────────────────────┘
                                │
                           HTTPS/TLS
                                │
┌─────────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                         │
├─────────────────────────────────────────────────────────────────┤
│                    Reverse Proxy (Optional)                    │
│               nginx │ Apache │ Cloudflare │ Load Balancer      │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    WEB APPLICATION LAYER                       │
├─────────────────────────────────────────────────────────────────┤
│                         Flask Framework                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │   Routes    │ │ Middleware  │ │  Templates  │ │ Static Files││
│  │             │ │             │ │             │ │             ││
│  │ /generate   │ │ Security    │ │ Jinja2      │ │ CSS/JS      ││
│  │ /verify     │ │ Headers     │ │ Templates   │ │ Images      ││
│  │ /analyze    │ │ CORS        │ │             │ │             ││
│  │ /version    │ │ Logging     │ │             │ │             ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION SERVER LAYER                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Development:                 Production:                      │
│  ┌─────────────────┐         ┌─────────────────┐              │
│  │ Flask Dev Server│         │   Gunicorn WSGI │              │
│  │                 │         │                 │              │
│  │ Single Process  │         │ Multi-Process   │              │
│  │ Auto-reload     │         │ Load Balancing  │              │
│  │ Debug Mode      │         │ Process Restart │              │
│  └─────────────────┘         └─────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                     BUSINESS LOGIC LAYER                       │
├─────────────────────────────────────────────────────────────────┤
│                        CsrGenerator Class                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │   Validation│ │ Key Generation │ CSR Creation│ │  Analysis   ││
│  │             │ │              │ │             │ │             ││
│  │ RFC Checks  │ │ RSA/ECDSA    │ │ X.509 CSR   │ │ Compliance  ││
│  │ Domain Val. │ │ Key Pairs    │ │ Extensions  │ │ Verification││
│  │ Field Limits│ │ Secure RNG   │ │ Subject Alt │ │ Matching    ││
│  │ Input Sanit.│ │              │ │ Names       │ │             ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                   CRYPTOGRAPHIC LAYER                          │
├─────────────────────────────────────────────────────────────────┤
│                    Python Cryptography Stack                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │Cryptography │ │  pyOpenSSL  │ │   OpenSSL   │ │  Hardware   ││
│  │   Library   │ │   Bindings  │ │   Library   │ │   Support   ││
│  │             │ │             │ │             │ │             ││
│  │ Modern API  │ │ Legacy API  │ │ Crypto Impl │ │ RNG/AES-NI  ││
│  │ Type Safety │ │ X.509 Utils │ │ Algorithms  │ │ Secure Enclav││
│  │ RFC Complian│ │ CSR Support │ │ ASN.1       │ │             ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                      SYSTEM LAYER                              │
├─────────────────────────────────────────────────────────────────┤
│                     Operating System                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │   Python    │ │   Network   │ │ File System │ │   Memory    ││
│  │  Runtime    │ │   Stack     │ │             │ │ Management  ││
│  │             │ │             │ │             │ │             ││
│  │ Interpreter │ │ TCP/IP      │ │ SSL Certs   │ │ Heap/Stack  ││
│  │ GIL         │ │ TLS/SSL     │ │ Static Files│ │ Garbage GC  ││
│  │ Modules     │ │ HTTP/HTTPS  │ │ Logs        │ │             ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Software Stack

### Runtime Environment
```
Python 3.9+
├── Core Dependencies
│   ├── Flask 3.1.1          (Web Framework)
│   ├── cryptography 45.0.4  (Modern Crypto Library)
│   ├── pyOpenSSL 25.1.0     (Legacy Crypto Support)
│   └── Gunicorn 23.0.0      (WSGI Server)
├── Development Dependencies
│   ├── pytest              (Testing Framework)
│   ├── flake8              (Code Linting)
│   └── coverage            (Test Coverage)
└── System Dependencies
    ├── OpenSSL Library
    ├── Operating System Crypto
    └── Hardware RNG Support
```

### Technology Stack Details

#### Web Framework Layer
- **Flask 3.1.1**: Lightweight WSGI web application framework
- **Jinja2 Templates**: Template engine for HTML rendering
- **Werkzeug**: WSGI utility library for request/response handling

#### Security Layer
- **TLS/HTTPS**: All communications encrypted
- **Security Headers**: XSS, CSRF, content-type protection
- **Input Validation**: Multi-layer validation and sanitization
- **Request Limiting**: Size and rate limiting

#### Cryptographic Stack
- **cryptography 45.0.4**: Modern, memory-safe cryptography
- **pyOpenSSL 25.1.0**: OpenSSL bindings for X.509 operations
- **OpenSSL**: Industry-standard cryptographic library
- **Hardware Support**: AES-NI, secure random number generation

## Layer Architecture

### Presentation Layer
**Responsibilities:**
- HTTP request handling
- Response formatting (HTML/JSON)
- Static file serving
- Client-side validation

**Components:**
- Flask routes (`app.py`)
- HTML templates (`templates/`)
- Static assets (`static/`)
- Error handlers

### Business Logic Layer
**Responsibilities:**
- CSR generation and validation
- Cryptographic operations
- RFC compliance checking
- Domain validation

**Components:**
- `CsrGenerator` class
- Validation methods
- Analysis functions
- Verification utilities

### Data Access Layer
**Responsibilities:**
- Certificate file operations
- Configuration management
- Logging and monitoring

**Components:**
- File system operations
- Configuration loading
- SSL certificate management

## Component Interactions

### Request Flow
```
┌─────────────┐    HTTP/HTTPS    ┌─────────────┐
│   Client    │ ───────────────→ │    Flask    │
│  Browser    │                  │   Routes    │
│   or API    │                  │             │
└─────────────┘                  └─────────────┘
                                        │
                                        ▼
                                ┌─────────────┐
                                │ Validation  │
                                │ Middleware  │
                                │             │
                                └─────────────┘
                                        │
                                        ▼
                                ┌─────────────┐
                                │CsrGenerator │
                                │   Class     │
                                │             │
                                └─────────────┘
                                        │
                                        ▼
                                ┌─────────────┐
                                │Cryptography │
                                │   Library   │
                                │             │
                                └─────────────┘
                                        │
                                        ▼
                                ┌─────────────┐
                                │   Response  │
                                │ (JSON/HTML) │
                                │             │
                                └─────────────┘
```

### Data Flow Architecture
```
Input Data → Validation → Processing → Output
    │            │           │           │
    │            │           │           ▼
    │            │           │     ┌─────────────┐
    │            │           │     │   JSON      │
    │            │           │     │  Response   │
    │            │           │     │             │
    │            │           │     │ - CSR       │
    │            │           │     │ - Private   │
    │            │           │     │   Key       │
    │            │           │     │ - Analysis  │
    │            │           │     │ - Status    │
    │            │           │     └─────────────┘
    │            │           │
    │            │           ▼
    │            │     ┌─────────────┐
    │            │     │Cryptographic│
    │            │     │ Operations  │
    │            │     │             │
    │            │     │ - Key Gen   │
    │            │     │ - CSR Build │
    │            │     │ - Signing   │
    │            │     │ - Analysis  │
    │            │     └─────────────┘
    │            │
    │            ▼
    │      ┌─────────────┐
    │      │ Input       │
    │      │ Validation  │
    │      │             │
    │      │ - Sanitize  │
    │      │ - RFC Check │
    │      │ - Limits    │
    │      │ - Security  │
    │      └─────────────┘
    │
    ▼
┌─────────────┐
│ Raw Input   │
│ Processing  │
│             │
│ - Form Data │
│ - JSON      │
│ - Files     │
│ - Headers   │
└─────────────┘
```

## Design Principles

### SOLID Principles Implementation

#### Single Responsibility Principle
- **Flask routes**: Handle only HTTP concerns
- **CsrGenerator**: Focused on CSR operations only
- **Validation functions**: Single-purpose validation
- **Security middleware**: Only security-related functionality

#### Open/Closed Principle
- **Key types**: Extensible without modifying existing code
- **Validation rules**: New rules can be added without changes
- **Analysis features**: Pluggable analysis modules

#### Liskov Substitution Principle
- **Key algorithms**: RSA/ECDSA interchangeable through common interface
- **Error responses**: Consistent format regardless of error type

#### Interface Segregation Principle
- **API endpoints**: Focused, specific interfaces
- **Static methods**: Segregated by functionality
- **Configuration**: Environment-specific interfaces

#### Dependency Inversion Principle
- **Cryptography abstraction**: Depends on interfaces, not implementations
- **Configuration**: Environment-based, not hardcoded
- **Testing**: Mock-friendly design

### Security-First Design

#### Defense in Depth
```
┌─────────────────────────────────────┐
│           Input Layer               │
│  ┌─────────────────────────────────┐│
│  │ Client-side validation (JS)     ││
│  │ Basic format checking           ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
                  │
┌─────────────────────────────────────┐
│         Transport Layer             │
│  ┌─────────────────────────────────┐│
│  │ HTTPS/TLS encryption            ││
│  │ Security headers                ││
│  │ Request size limits             ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
                  │
┌─────────────────────────────────────┐
│       Application Layer             │
│  ┌─────────────────────────────────┐│
│  │ Server-side validation          ││
│  │ Input sanitization              ││
│  │ Authentication (future)         ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
                  │
┌─────────────────────────────────────┐
│         Business Layer              │
│  ┌─────────────────────────────────┐│
│  │ RFC compliance checking         ││
│  │ Cryptographic validation        ││
│  │ Domain security policies        ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
                  │
┌─────────────────────────────────────┐
│         Data Layer                  │
│  ┌─────────────────────────────────┐│
│  │ Secure key generation           ││
│  │ Memory protection               ││
│  │ Audit logging                   ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
```

#### Fail-Safe Defaults
- **HTTPS enabled by default**
- **Secure session cookie settings**
- **Conservative cryptographic parameters**
- **Restrictive validation rules**
- **Minimal error information disclosure**

### Performance Design

#### Stateless Architecture
- No session state stored on server
- Each request is independent
- Horizontal scaling capability
- Load balancer friendly

#### Efficient Resource Usage
- Minimal memory footprint
- CPU-appropriate crypto algorithms
- Lazy loading of heavy operations
- Proper cleanup of cryptographic materials

## Security Architecture

### Trust Boundaries
```
Internet ←→ [TLS] ←→ Web Server ←→ [Validation] ←→ Application ←→ [Crypto] ←→ System
   │                    │                          │                    │
   │                    │                          │                    │
Untrusted         Semi-trusted              Trusted                Trusted
 Domain            Domain                   Domain                 Domain
```

### Security Controls by Layer

#### Network Security
- **TLS 1.2+ required**
- **HSTS headers**
- **Secure cipher suites**
- **Certificate validation**

#### Application Security
- **Input validation and sanitization**
- **Output encoding**
- **Error handling without information leakage**
- **Logging with sanitization**

#### Cryptographic Security
- **Modern algorithms only** (RSA 2048+, ECDSA P-256+)
- **Secure random number generation**
- **Proper key handling**
- **Algorithm agility**

## Deployment Models

### Development Deployment
```
Developer Machine
├── Flask Development Server
├── Self-signed Certificates
├── Debug Mode Enabled
├── Auto-reload
└── Local File System
```

### Production Deployment
```
Production Server
├── Gunicorn WSGI Server
│   ├── Multiple Worker Processes
│   ├── Process Management
│   └── Health Monitoring
├── Reverse Proxy (Optional)
│   ├── nginx/Apache
│   ├── SSL Termination
│   └── Load Balancing
├── Valid SSL Certificates
├── Environment Configuration
└── Log Management
```

### Container Deployment
```
Docker Container
├── Python Runtime
├── Application Code
├── Dependencies
├── SSL Certificates (mounted)
├── Configuration (environment)
└── Port Exposure (5555)
```

## Best Practices Implemented

### Code Quality
- **Type hints where beneficial**
- **Comprehensive docstrings**
- **Consistent code style**
- **Modular design**
- **DRY principle adherence**

### Testing Strategy
- **Unit tests for core functionality**
- **Security-specific test suite**
- **Integration testing**
- **Input validation testing**
- **Error condition testing**

### Configuration Management
- **Environment-based configuration**
- **Sensible defaults**
- **Configuration validation**
- **Secret management**

### Monitoring and Observability
- **Structured logging**
- **Error tracking**
- **Performance monitoring**
- **Security event logging**

### Documentation
- **API documentation**
- **Security policy**
- **Deployment guides**
- **Architecture documentation**

This architecture supports the application's security-focused mission while maintaining simplicity, reliability, and maintainability. The layered approach ensures clear separation of concerns and enables independent testing and modification of each layer.
