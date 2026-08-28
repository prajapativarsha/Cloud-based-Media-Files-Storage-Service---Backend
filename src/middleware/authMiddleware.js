import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'super-long-random';

export const requireAuth = (req, res, next) => {
  // 1. Extract the token from the httpOnly cookie
  const token = req.cookies.accessToken;

  // 2. Block request if no token exists
  if (!token) {
    return res.status(401).json({ 
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' } 
    });
  }

  // 3. Verify the token signature and expiration
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Attach the decoded payload (e.g., { userId: '...' }) to the request object
    req.user = decoded; 
    
    // Pass control to the next middleware or route handler
    next();
  } catch (error) {
    // Return the exact error format specified in your project requirements
    return res.status(403).json({ 
      error: { code: 'FORBIDDEN', message: 'Invalid or expired token' } 
    });
  }
};