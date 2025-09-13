# Document Management API

## Overview
This project is a backend API for a document management system, built using Node.js, Express, and MongoDB. It supports user authentication (both email/password and Google OAuth) and provides endpoints for creating, reading, updating, and deleting (CRUD) documents associated with authenticated users. The API uses JSON Web Tokens (JWT) and Firebase Admin SDK for authentication and MongoDB for data storage.

## Features
- **User Authentication**:
  - Register and login with email and password.
  - Google OAuth integration for user authentication.
- **Document Management**:
  - Create, retrieve, update, and delete documents.
  - Documents are tied to specific users via `userId`.
- **Security**:
  - Passwords are hashed using `bcryptjs`.
  - JWT and Firebase token verification for secure access.
  - CORS support for cross-origin requests.
- **Database**: MongoDB for storing user and document data.

## Prerequisites
- Node.js (v14 or higher)
- MongoDB (local or cloud instance, e.g., MongoDB Atlas)
- Firebase project with Admin SDK credentials
- Environment variables configured in a `.env` file

## Installation
1. **Clone the repository**:
   ```bash
   git clone "https://github.com/siefeldeen1/Mindflow_backend.git"
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Set up environment variables**:
   Create a `.env` file in the root directory with the following variables:
   ```env
   MONGODB_URI=<your-mongodb-connection-string>
   JWT_SECRET=<your-jwt-secret-key>
   FIREBASE_PROJECT_ID=<your-firebase-project-id>
   FIREBASE_PRIVATE_KEY=<your-firebase-private-key>
   FIREBASE_CLIENT_EMAIL=<your-firebase-client-email>
   PORT=5000
   ```
   - Replace `<your-mongodb-connection-string>` with your MongoDB connection string.
   - Replace `<your-jwt-secret-key>` with a secure secret for JWT signing.
   - Obtain Firebase Admin SDK credentials from your Firebase project and add the `projectId`, `privateKey`, and `clientEmail`.

4. **Run the server**:
   ```bash
   npm start
   ```
   The server will start on `http://localhost:5000` (or the port specified in `PORT`).

## API Endpoints

### Authentication
- **POST /api/auth/register**
  - Register a new user with email, password, and name.
  - Request body: `{ "email": string, "password": string, "name": string }`
  - Response: `{ user: { id, email, name }, token }`
- **POST /api/auth/login**
  - Login with email and password.
  - Request body: `{ "email": string, "password": string }`
  - Response: `{ user: { id, email, name }, token }`
- **POST /api/auth/google**
  - Authenticate using a Google OAuth token.
  - Request body: `{ "token": string }`
  - Response: `{ user: { id, email, name }, token }`

### Documents
All document endpoints require an `Authorization` header with a Bearer token (JWT or Firebase token).

- **GET /api/documents**
  - Retrieve all documents for the authenticated user.
  - Response: Array of documents
- **GET /api/documents/:id**
  - Retrieve a specific document by ID.
  - Response: Document object or 404 if not found
- **POST /api/documents**
  - Create or update a document.
  - Request body: `{ "id": string, "name": string, "state": object }`
  - Response: Created/updated document
- **PUT /api/documents**
  - Update a document.
  - Request body: `{ "id": string, "name": string, "state": object }`
  - Response: Updated document or 404 if not found
- **DELETE /api/documents/:id**
  - Delete a document by ID.
  - Response: `{ success: true }` or 404 if not found

## Project Structure
- `index.js`: Main application file containing Express setup, MongoDB connection, schemas, and API routes.
- `.env`: Environment variables for configuration (not included in version control).
- `node_modules/`: Dependencies installed via npm.
- `package.json`: Project metadata and dependencies.

## Dependencies
- `express`: Web framework for Node.js
- `mongoose`: MongoDB object modeling
- `cors`: Enable cross-origin resource sharing
- `uuid`: Generate unique IDs
- `bcryptjs`: Password hashing
- `jsonwebtoken`: JWT generation and verification
- `firebase-admin`: Firebase Admin SDK for Google OAuth
- `dotenv`: Load environment variables

## Error Handling
- The API returns appropriate HTTP status codes (e.g., 400 for bad requests, 401 for unauthorized, 404 for not found, 500 for server errors).
- Error responses include an `error` field with a descriptive message.

## Security Notes
- Ensure the `.env` file is not exposed in version control.
- Use a strong `JWT_SECRET` for token signing.
- Validate Firebase credentials and keep them secure.
- Consider implementing rate limiting for production to prevent abuse.

## Future Improvements
- Add input validation middleware (e.g., using `express-validator`).
- Implement pagination for the `/api/documents` endpoint.
- Add support for document sharing between users.
- Include unit tests using a framework like Jest.

## License
This project is licensed under the MIT License.
