# CRUD API Project with .NET 8 and Clean Architecture

This project is a CRUD (Create, Read, Update, Delete) API built using .NET 8 and adhering to the principles of Clean Architecture. It provides endpoints for managing resources with role-based JWT authorization.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Authentication and Authorization](#authentication-and-authorization)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Contributing](#contributing)
- [License](#license)

## Overview

This API project aims to provide a robust and scalable solution for managing resources through CRUD operations. It follows the Clean Architecture principles, which emphasize separation of concerns and maintainability. The project is designed to be extensible, allowing easy integration of additional features and scalability to meet future requirements.

## Features

- Create, Read, Update, and Delete operations for resources
- Role-based JWT authorization for secure access control
- Clean Architecture for maintainability and scalability
- Swagger documentation for API endpoints
- Logging and error handling for improved debugging and monitoring

## Prerequisites

Before you begin, ensure you have met the following requirements:

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) installed on your machine
- [SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) or another supported database management system installed
- An understanding of JWT authentication and authorization concepts

## Installation

1. Clone the repository to your local machine:

2. Navigate to the project directory:

3. Restore the NuGet packages:

   ```bash
   dotnet restore
   ```

4. Update the database connection string in `appsettings.json` with your database details.

5. Run the database migrations to create the necessary tables:

   ```bash
   dotnet ef database update
   ```

## Usage

To start the API server, run the following command:

```bash
dotnet run
```

The API server will start listening on the specified port (default is `5000`).

## Authentication and Authorization

This project uses JWT (JSON Web Tokens) for authentication and role-based authorization. To access protected endpoints, you need to include a valid JWT token in the `Authorization` header of your HTTP requests. The token should include the appropriate role claims required for accessing specific resources.

## Project Structure

The project follows a modular structure based on Clean Architecture principles:

- **Application**: Contains application logic and use cases.
- **Domain**: Contains domain entities and business logic.
- **Infrastructure**: Contains implementations for data access, external services, and cross-cutting concerns.
- **Presentation**: Contains API controllers and DTOs for handling HTTP requests and responses.

## Technologies Used

- .NET 8
- ASP.NET Core
- Entity Framework Core
- JWT Authentication
- Swagger UI
- Serilog (for logging)
