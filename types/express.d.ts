declare global {
  namespace Express {
    interface AuthenticatedUser {
      uid: string;
      email: string;
      emailVerified: boolean;
    }

    interface Request {
      user?: AuthenticatedUser;
      requestId?: string;
      rawBody?: Buffer;
    }
  }
}

export {};
