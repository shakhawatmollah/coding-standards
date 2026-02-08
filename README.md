# Full-Stack Coding Standards & Best Practices Guide

**Tech Stack:** Node.js | Angular | PostgreSQL | Docker | CI/CD | Nginx

**Version:** 1.0  
**Last Updated:** February 2026

---

## Table of Contents

1. [General Principles](#general-principles)
2. [Node.js Backend Standards](#nodejs-backend-standards)
3. [Angular Frontend Standards](#angular-frontend-standards)
4. [PostgreSQL Database Standards](#postgresql-database-standards)
5. [Docker Standards](#docker-standards)
6. [CI/CD Pipeline Standards](#cicd-pipeline-standards)
7. [Nginx Configuration Standards](#nginx-configuration-standards)
8. [Security Best Practices](#security-best-practices)
9. [Code Review Checklist](#code-review-checklist)

---

## General Principles

### Core Values
- **Readability over cleverness** - Code is read 10x more than written
- **Consistency** - Follow established patterns within the codebase
- **Security first** - Never compromise on security for convenience
- **Test coverage** - Aim for 80%+ coverage on critical paths
- **Documentation** - Code should be self-documenting; comments explain "why", not "what"

### Naming Conventions

✅ **DO:**
```javascript
// Use descriptive, meaningful names
const userAuthenticationToken = generateToken();
const isEmailVerified = checkEmailStatus();
const MAX_RETRY_ATTEMPTS = 3;
```

❌ **DON'T:**
```javascript
// Avoid cryptic abbreviations
const uatk = genTok();
const ev = chkEm();
const MAX = 3;
```

---

## Node.js Backend Standards

### Project Structure

✅ **DO:** Follow a clean architecture pattern
```
src/
├── config/           # Configuration files
├── controllers/      # Route controllers
├── services/         # Business logic
├── models/          # Data models
├── middleware/      # Custom middleware
├── utils/           # Helper functions
├── validators/      # Input validation schemas
├── routes/          # Route definitions
└── tests/           # Test files
```

### Error Handling

✅ **DO:** Use async/await with proper error handling
```javascript
// Good: Centralized error handling
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Controller example
const getUserById = async (req, res, next) => {
  try {
    const user = await userService.findById(req.params.id);
    
    if (!user) {
      throw new AppError('User not found', 404);
    }
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (error) {
    next(error); // Pass to error middleware
  }
};

// Global error middleware
app.use((err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  
  if (process.env.NODE_ENV === 'development') {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      stack: err.stack,
      error: err
    });
  } else {
    // Production: don't leak error details
    res.status(err.statusCode).json({
      status: err.status,
      message: err.isOperational ? err.message : 'Something went wrong'
    });
  }
});
```

❌ **DON'T:** Use callbacks or swallow errors
```javascript
// Bad: Callback hell
getUserById(id, function(err, user) {
  if (err) {
    console.log(err); // Just logging, not handling!
  }
  getOrders(user.id, function(err, orders) {
    // Nested callbacks...
  });
});

// Bad: Empty catch block
try {
  await riskyOperation();
} catch (error) {
  // Silent failure - never do this!
}
```

### Environment Variables

✅ **DO:** Use environment variables for configuration
```javascript
// config/database.js
require('dotenv').config();

module.exports = {
  database: {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10),
    name: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: process.env.NODE_ENV === 'production'
  }
};

// .env (never commit this file!)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
DB_USER=dbuser
DB_PASSWORD=securepassword123
NODE_ENV=development
JWT_SECRET=your-super-secret-jwt-key
```

❌ **DON'T:** Hardcode credentials
```javascript
// Bad: Hardcoded secrets
const dbConfig = {
  host: 'localhost',
  password: 'admin123', // Never!
  apiKey: 'sk-1234567890' // Never!
};
```

### Input Validation

✅ **DO:** Validate and sanitize all inputs
```javascript
// Using Joi for validation
const Joi = require('joi');

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required(),
  name: Joi.string().min(2).max(100).trim().required(),
  age: Joi.number().integer().min(13).max(120).optional()
});

// Middleware
const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));
      
      return res.status(400).json({
        status: 'fail',
        errors
      });
    }
    
    req.validatedBody = value;
    next();
  };
};

// Usage
router.post('/users', validateRequest(userSchema), createUser);
```

❌ **DON'T:** Trust user input
```javascript
// Bad: No validation
app.post('/users', (req, res) => {
  const user = new User(req.body); // Dangerous!
  user.save();
});
```

### Database Queries (with PostgreSQL)

✅ **DO:** Use parameterized queries
```javascript
// Good: Protected against SQL injection
const getUserByEmail = async (email) => {
  const query = 'SELECT * FROM users WHERE email = $1';
  const result = await pool.query(query, [email]);
  return result.rows[0];
};

// Good: Transaction handling
const transferFunds = async (fromAccount, toAccount, amount) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE id = $2',
      [amount, fromAccount]
    );
    
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2',
      [amount, toAccount]
    );
    
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
};
```

❌ **DON'T:** Use string concatenation for queries
```javascript
// Bad: SQL injection vulnerability!
const query = `SELECT * FROM users WHERE email = '${email}'`;
pool.query(query); // Never do this!

// Bad: No transaction for related operations
await pool.query('UPDATE accounts SET balance = balance - 100 WHERE id = 1');
await pool.query('UPDATE accounts SET balance = balance + 100 WHERE id = 2');
// What if second query fails? Data inconsistency!
```

### Authentication & Authorization

✅ **DO:** Implement proper JWT handling
```javascript
// Good: Secure JWT implementation
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 12;
const JWT_EXPIRES_IN = '1h';
const REFRESH_TOKEN_EXPIRES_IN = '7d';

// Hash password
const hashPassword = async (password) => {
  return await bcrypt.hash(password, SALT_ROUNDS);
};

// Generate tokens
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { userId, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
  
  const refreshToken = jwt.sign(
    { userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
  );
  
  return { accessToken, refreshToken };
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (decoded.type !== 'access') {
      return res.status(401).json({ message: 'Invalid token type' });
    }
    
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Role-based authorization
const authorize = (...allowedRoles) => {
  return async (req, res, next) => {
    const user = await User.findById(req.userId);
    
    if (!user || !allowedRoles.includes(user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }
    
    next();
  };
};

// Usage
router.delete('/users/:id', 
  authenticateToken, 
  authorize('admin', 'superadmin'), 
  deleteUser
);
```

❌ **DON'T:** Store passwords in plain text or use weak hashing
```javascript
// Bad: Plain text password
const user = {
  email: 'user@example.com',
  password: 'password123' // Never!
};

// Bad: Weak or no expiration
const token = jwt.sign({ userId }, 'weak-secret'); // No expiration!
```

### Logging

✅ **DO:** Use structured logging
```javascript
// Good: Structured logging with Winston
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log' 
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Usage
logger.info('User logged in', { userId: user.id, ip: req.ip });
logger.error('Database connection failed', { error: err.message });
```

❌ **DON'T:** Use console.log in production
```javascript
// Bad: Unstructured logging
console.log('User logged in'); // No context, no levels
console.log(sensitiveData); // Might log secrets!
```

### API Response Format

✅ **DO:** Use consistent response structure
```javascript
// Good: Standardized response
const successResponse = (res, data, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({
    status: 'success',
    message,
    data,
    timestamp: new Date().toISOString()
  });
};

const errorResponse = (res, message, statusCode = 500, errors = null) => {
  return res.status(statusCode).json({
    status: 'error',
    message,
    errors,
    timestamp: new Date().toISOString()
  });
};

// Usage
successResponse(res, { user }, 'User created successfully', 201);
errorResponse(res, 'Validation failed', 400, validationErrors);
```

### Rate Limiting

✅ **DO:** Implement rate limiting
```javascript
// Good: Protect against brute force
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', { 
      ip: req.ip, 
      endpoint: req.path 
    });
    res.status(429).json({
      status: 'error',
      message: 'Too many requests, please try again later'
    });
  }
});

app.use('/api/auth/login', loginLimiter);

// API-wide rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100 // 100 requests per minute
});

app.use('/api/', apiLimiter);
```

---

## Angular Frontend Standards

### Project Structure

✅ **DO:** Follow Angular style guide structure
```
src/app/
├── core/                 # Singleton services, guards
│   ├── guards/
│   ├── interceptors/
│   ├── services/
│   └── core.module.ts
├── shared/              # Shared components, directives, pipes
│   ├── components/
│   ├── directives/
│   ├── pipes/
│   └── shared.module.ts
├── features/            # Feature modules
│   ├── user/
│   │   ├── components/
│   │   ├── services/
│   │   ├── models/
│   │   └── user.module.ts
│   └── dashboard/
└── app.component.ts
```

### Component Best Practices

✅ **DO:** Keep components focused and testable
```typescript
// Good: Single responsibility, clear inputs/outputs
@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class UserProfileComponent implements OnInit, OnDestroy {
  @Input() userId!: string;
  @Output() profileUpdated = new EventEmitter<User>();
  
  user$!: Observable<User>;
  private destroy$ = new Subject<void>();
  
  constructor(
    private userService: UserService,
    private notificationService: NotificationService
  ) {}
  
  ngOnInit(): void {
    this.loadUser();
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
  
  private loadUser(): void {
    this.user$ = this.userService.getUser(this.userId).pipe(
      takeUntil(this.destroy$),
      catchError(error => {
        this.notificationService.error('Failed to load user');
        return of(null);
      })
    );
  }
  
  updateProfile(user: User): void {
    this.userService.updateUser(user).pipe(
      takeUntil(this.destroy$)
    ).subscribe({
      next: (updatedUser) => {
        this.profileUpdated.emit(updatedUser);
        this.notificationService.success('Profile updated');
      },
      error: (error) => {
        this.notificationService.error('Update failed');
      }
    });
  }
}
```

❌ **DON'T:** Create god components or forget unsubscribe
```typescript
// Bad: Too many responsibilities, memory leaks
@Component({
  selector: 'app-dashboard',
  template: '...'
})
export class DashboardComponent {
  users: User[] = [];
  orders: Order[] = [];
  analytics: any;
  
  constructor(
    private userService: UserService,
    private orderService: OrderService,
    private analyticsService: AnalyticsService,
    private authService: AuthService,
    private router: Router
  ) {
    // Bad: Subscription without unsubscribe
    this.userService.getUsers().subscribe(users => {
      this.users = users;
    });
    
    // Bad: Business logic in constructor
    if (this.authService.isAdmin()) {
      this.loadAdminData();
    }
  }
}
```

### Service Best Practices

✅ **DO:** Use services for business logic and HTTP calls
```typescript
// Good: Clean service with error handling
@Injectable({
  providedIn: 'root'
})
export class UserService {
  private readonly API_URL = environment.apiUrl;
  private readonly CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
  
  private userCache$ = new BehaviorSubject<Map<string, User>>(new Map());
  
  constructor(
    private http: HttpClient,
    private logger: LoggerService
  ) {}
  
  getUser(id: string): Observable<User> {
    const cached = this.userCache$.value.get(id);
    
    if (cached) {
      return of(cached);
    }
    
    return this.http.get<ApiResponse<User>>(`${this.API_URL}/users/${id}`).pipe(
      map(response => response.data),
      tap(user => this.updateCache(id, user)),
      catchError(error => {
        this.logger.error('Failed to fetch user', { id, error });
        return throwError(() => new Error('Failed to load user data'));
      })
    );
  }
  
  updateUser(user: User): Observable<User> {
    return this.http.put<ApiResponse<User>>(
      `${this.API_URL}/users/${user.id}`, 
      user
    ).pipe(
      map(response => response.data),
      tap(updatedUser => {
        this.updateCache(user.id, updatedUser);
        this.logger.info('User updated', { userId: user.id });
      }),
      catchError(this.handleError)
    );
  }
  
  private updateCache(id: string, user: User): void {
    const cache = this.userCache$.value;
    cache.set(id, user);
    this.userCache$.next(cache);
  }
  
  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'An error occurred';
    
    if (error.error instanceof ErrorEvent) {
      errorMessage = `Client error: ${error.error.message}`;
    } else {
      errorMessage = `Server error: ${error.status} - ${error.message}`;
    }
    
    return throwError(() => new Error(errorMessage));
  }
}
```

### HTTP Interceptors

✅ **DO:** Use interceptors for cross-cutting concerns
```typescript
// Good: Auth interceptor
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private authService: AuthService) {}
  
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = this.authService.getToken();
    
    if (token) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
    }
    
    return next.handle(req);
  }
}

// Good: Error interceptor
@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
  constructor(
    private notificationService: NotificationService,
    private authService: AuthService,
    private router: Router
  ) {}
  
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(req).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          this.authService.logout();
          this.router.navigate(['/login']);
        } else if (error.status === 403) {
          this.notificationService.error('Access denied');
        } else if (error.status >= 500) {
          this.notificationService.error('Server error occurred');
        }
        
        return throwError(() => error);
      })
    );
  }
}
```

### Form Validation

✅ **DO:** Use reactive forms with validation
```typescript
// Good: Reactive form with custom validators
export class UserFormComponent implements OnInit {
  userForm!: FormGroup;
  
  constructor(private fb: FormBuilder) {}
  
  ngOnInit(): void {
    this.userForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [
        Validators.required,
        Validators.minLength(8),
        this.passwordStrengthValidator
      ]],
      confirmPassword: ['', Validators.required],
      age: ['', [Validators.min(13), Validators.max(120)]],
      terms: [false, Validators.requiredTrue]
    }, {
      validators: this.passwordMatchValidator
    });
  }
  
  private passwordStrengthValidator(control: AbstractControl): ValidationErrors | null {
    const value = control.value;
    
    if (!value) return null;
    
    const hasNumber = /[0-9]/.test(value);
    const hasUpper = /[A-Z]/.test(value);
    const hasLower = /[a-z]/.test(value);
    const hasSpecial = /[!@#$%^&*]/.test(value);
    
    const valid = hasNumber && hasUpper && hasLower && hasSpecial;
    
    return valid ? null : { passwordStrength: true };
  }
  
  private passwordMatchValidator(group: AbstractControl): ValidationErrors | null {
    const password = group.get('password')?.value;
    const confirmPassword = group.get('confirmPassword')?.value;
    
    return password === confirmPassword ? null : { passwordMismatch: true };
  }
  
  get email() { return this.userForm.get('email'); }
  get password() { return this.userForm.get('password'); }
  
  onSubmit(): void {
    if (this.userForm.invalid) {
      this.userForm.markAllAsTouched();
      return;
    }
    
    const formValue = this.userForm.value;
    // Process form...
  }
}
```

### State Management (NgRx)

✅ **DO:** Use NgRx for complex state
```typescript
// Good: Well-structured NgRx implementation

// Actions
export const loadUsers = createAction('[User List] Load Users');
export const loadUsersSuccess = createAction(
  '[User API] Load Users Success',
  props<{ users: User[] }>()
);
export const loadUsersFailure = createAction(
  '[User API] Load Users Failure',
  props<{ error: string }>()
);

// Reducer
export interface UserState {
  users: User[];
  loading: boolean;
  error: string | null;
}

const initialState: UserState = {
  users: [],
  loading: false,
  error: null
};

export const userReducer = createReducer(
  initialState,
  on(loadUsers, state => ({ ...state, loading: true, error: null })),
  on(loadUsersSuccess, (state, { users }) => ({
    ...state,
    users,
    loading: false
  })),
  on(loadUsersFailure, (state, { error }) => ({
    ...state,
    error,
    loading: false
  }))
);

// Effects
@Injectable()
export class UserEffects {
  loadUsers$ = createEffect(() =>
    this.actions$.pipe(
      ofType(loadUsers),
      exhaustMap(() =>
        this.userService.getUsers().pipe(
          map(users => loadUsersSuccess({ users })),
          catchError(error => of(loadUsersFailure({ error: error.message })))
        )
      )
    )
  );
  
  constructor(
    private actions$: Actions,
    private userService: UserService
  ) {}
}

// Selectors
export const selectUserState = createFeatureSelector<UserState>('users');
export const selectAllUsers = createSelector(
  selectUserState,
  state => state.users
);
export const selectUsersLoading = createSelector(
  selectUserState,
  state => state.loading
);
```

### Security in Angular

✅ **DO:** Sanitize user input and use Angular's built-in security
```typescript
// Good: Sanitization
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-content-display',
  template: `<div [innerHTML]="safeContent"></div>`
})
export class ContentDisplayComponent {
  safeContent!: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer) {}
  
  setContent(userContent: string): void {
    // Angular sanitizes by default, but for explicit trust:
    this.safeContent = this.sanitizer.sanitize(
      SecurityContext.HTML, 
      userContent
    ) || '';
  }
}

// Good: XSS protection in forms
this.userForm = this.fb.group({
  comment: ['', [
    Validators.required,
    this.noScriptTagValidator
  ]]
});

private noScriptTagValidator(control: AbstractControl): ValidationErrors | null {
  const value = control.value;
  if (/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi.test(value)) {
    return { scriptTag: true };
  }
  return null;
}
```

❌ **DON'T:** Bypass Angular's security
```typescript
// Bad: Bypassing sanitization
this.innerHTML = this.sanitizer.bypassSecurityTrustHtml(userInput); // Dangerous!
```

---

## PostgreSQL Database Standards

### Schema Design

✅ **DO:** Follow normalization and use appropriate data types
```sql
-- Good: Normalized schema with constraints
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    email_verified_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT valid_role CHECK (role IN ('user', 'admin', 'superadmin'))
);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON user_sessions(expires_at);
```

❌ **DON'T:** Use poor data types or skip constraints
```sql
-- Bad: Wrong data types, no constraints
CREATE TABLE users (
    id VARCHAR(50), -- Should use UUID or SERIAL
    email TEXT, -- Too permissive
    password TEXT, -- No hash indication
    created VARCHAR(50) -- Should be TIMESTAMP
);
```

### Migrations

✅ **DO:** Use versioned migrations
```sql
-- migrations/001_create_users_table.up.sql
BEGIN;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    -- ... rest of schema
);

CREATE INDEX idx_users_email ON users(email);

COMMIT;

-- migrations/001_create_users_table.down.sql
BEGIN;

DROP TABLE IF EXISTS users CASCADE;

COMMIT;
```

### Query Optimization

✅ **DO:** Use EXPLAIN ANALYZE and optimize queries
```sql
-- Good: Optimized query with proper indexing
EXPLAIN ANALYZE
SELECT u.id, u.email, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.created_at >= CURRENT_DATE - INTERVAL '30 days'
  AND u.is_active = true
GROUP BY u.id, u.email
HAVING COUNT(o.id) > 5
ORDER BY order_count DESC
LIMIT 100;

-- Good: Use CTEs for complex queries
WITH active_users AS (
    SELECT id, email
    FROM users
    WHERE is_active = true
      AND deleted_at IS NULL
),
recent_orders AS (
    SELECT user_id, COUNT(*) as order_count
    FROM orders
    WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
    GROUP BY user_id
)
SELECT au.email, COALESCE(ro.order_count, 0) as orders
FROM active_users au
LEFT JOIN recent_orders ro ON au.id = ro.user_id
ORDER BY orders DESC;
```

❌ **DON'T:** Write inefficient queries
```sql
-- Bad: N+1 query pattern
SELECT * FROM users; -- Then for each user:
SELECT * FROM orders WHERE user_id = ?;

-- Bad: SELECT *
SELECT * FROM users WHERE email = 'test@example.com';
-- Always specify columns you need
```

### Indexes

✅ **DO:** Create appropriate indexes
```sql
-- Good: Composite index for common query patterns
CREATE INDEX idx_orders_user_status ON orders(user_id, status);
CREATE INDEX idx_orders_created_at ON orders(created_at DESC);

-- Good: Partial index for common filters
CREATE INDEX idx_active_users ON users(email) 
WHERE is_active = true AND deleted_at IS NULL;

-- Good: Index on foreign keys
CREATE INDEX idx_orders_user_id ON orders(user_id);
```

❌ **DON'T:** Over-index or under-index
```sql
-- Bad: Too many indexes (slows down writes)
CREATE INDEX idx1 ON users(email);
CREATE INDEX idx2 ON users(first_name);
CREATE INDEX idx3 ON users(last_name);
CREATE INDEX idx4 ON users(created_at);
-- ... and 10 more

-- Bad: No indexes on foreign keys
-- Missing: CREATE INDEX idx_orders_user_id ON orders(user_id);
```

### Transactions & Locking

✅ **DO:** Use transactions properly
```sql
-- Good: Explicit transaction with error handling
BEGIN;

-- Lock row to prevent concurrent modifications
SELECT * FROM accounts 
WHERE id = '123' 
FOR UPDATE;

UPDATE accounts 
SET balance = balance - 100 
WHERE id = '123' AND balance >= 100;

UPDATE accounts 
SET balance = balance + 100 
WHERE id = '456';

COMMIT;

-- Good: Use appropriate isolation levels
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
BEGIN;
-- Critical operations
COMMIT;
```

### Database Functions & Triggers

✅ **DO:** Use functions for complex logic
```sql
-- Good: Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Good: Audit trail trigger
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(50) NOT NULL,
    record_id UUID NOT NULL,
    action VARCHAR(10) NOT NULL,
    old_data JSONB,
    new_data JSONB,
    user_id UUID,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, old_data, new_data)
    VALUES (
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        TG_OP,
        to_jsonb(OLD),
        to_jsonb(NEW)
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
```

---

## Docker Standards

### Dockerfile Best Practices

✅ **DO:** Create optimized, secure Dockerfiles
```dockerfile
# Good: Multi-stage build for Node.js
# Stage 1: Build
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files first (better caching)
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Build application
RUN npm run build

# Stage 2: Production
FROM node:18-alpine

# Security: Run as non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy only necessary files from builder
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start application
CMD ["node", "dist/main.js"]
```

❌ **DON'T:** Create bloated or insecure images
```dockerfile
# Bad: Many issues
FROM node:18  # Not using Alpine (larger image)

WORKDIR /app

# Bad: Copying everything first (poor caching)
COPY . .

RUN npm install  # Should use npm ci

# Bad: Running as root
# Bad: No health check
# Bad: Exposing unnecessary ports
EXPOSE 3000 5432 6379

CMD npm start  # Should use node directly
```

### Docker Compose

✅ **DO:** Use docker-compose for local development
```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      target: development
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DB_HOST=postgres
      - REDIS_HOST=redis
    env_file:
      - .env
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - app-network
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - app-network
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    networks:
      - app-network
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - app-network
    restart: unless-stopped

volumes:
  postgres-data:
  redis-data:

networks:
  app-network:
    driver: bridge
```

### .dockerignore

✅ **DO:** Exclude unnecessary files
```
# .dockerignore
node_modules
npm-debug.log
dist
.git
.gitignore
.env
.env.local
.DS_Store
*.md
coverage
.vscode
.idea
logs
*.log
```

---

## CI/CD Pipeline Standards

### GitHub Actions Example

✅ **DO:** Implement comprehensive CI/CD
```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  NODE_VERSION: '18'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    name: Test
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: test_db
          POSTGRES_USER: test_user
          POSTGRES_PASSWORD: test_password
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run linter
        run: npm run lint
      
      - name: Run type check
        run: npm run type-check
      
      - name: Run unit tests
        run: npm run test:unit
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_NAME: test_db
          DB_USER: test_user
          DB_PASSWORD: test_password
      
      - name: Run integration tests
        run: npm run test:integration
      
      - name: Generate coverage report
        run: npm run test:coverage
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage/coverage-final.json
          fail_ci_if_error: true

  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Run npm audit
        run: npm audit --audit-level=high
      
      - name: Run Snyk security scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

  build:
    name: Build Docker Image
    runs-on: ubuntu-latest
    needs: [test, security-scan]
    if: github.event_name == 'push'
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
      
      - name: Log in to Container Registry
        uses: docker/login-action@v2
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v4
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=sha,prefix={{branch}}-
            type=semver,pattern={{version}}
      
      - name: Build and push Docker image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          build-args: |
            NODE_ENV=production

  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/develop'
    environment:
      name: staging
      url: https://staging.example.com
    
    steps:
      - name: Deploy to staging
        run: |
          echo "Deploying to staging environment"
          # Add your deployment commands here
          # e.g., kubectl, helm, ssh, etc.

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://example.com
    
    steps:
      - name: Deploy to production
        run: |
          echo "Deploying to production environment"
          # Add your deployment commands here
```

### GitLab CI Example

✅ **DO:** Alternative CI/CD with GitLab
```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"
  NODE_VERSION: "18"

.node_template: &node_template
  image: node:18-alpine
  cache:
    key:
      files:
        - package-lock.json
    paths:
      - node_modules/
  before_script:
    - npm ci

test:unit:
  <<: *node_template
  stage: test
  script:
    - npm run lint
    - npm run test:unit
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml
      junit: junit.xml

test:integration:
  <<: *node_template
  stage: test
  services:
    - postgres:15
  variables:
    POSTGRES_DB: test_db
    POSTGRES_USER: test_user
    POSTGRES_PASSWORD: test_password
    DB_HOST: postgres
  script:
    - npm run test:integration

security:audit:
  <<: *node_template
  stage: test
  script:
    - npm audit --audit-level=high
  allow_failure: false

build:docker:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
  only:
    - main
    - develop

deploy:staging:
  stage: deploy
  environment:
    name: staging
    url: https://staging.example.com
  script:
    - echo "Deploy to staging"
  only:
    - develop

deploy:production:
  stage: deploy
  environment:
    name: production
    url: https://example.com
  script:
    - echo "Deploy to production"
  when: manual
  only:
    - main
```

---

## Nginx Configuration Standards

### Main Configuration

✅ **DO:** Secure and optimized Nginx config
```nginx
# nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 20M;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml font/truetype font/opentype 
               application/vnd.ms-fontobject image/svg+xml;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    # Include virtual host configs
    include /etc/nginx/conf.d/*.conf;
}
```

### Site Configuration

✅ **DO:** Proper reverse proxy and SSL
```nginx
# /etc/nginx/conf.d/app.conf

# Upstream backend
upstream backend {
    least_conn;
    server app:3000 max_fails=3 fail_timeout=30s;
    server app:3001 max_fails=3 fail_timeout=30s backup;
    keepalive 32;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;

    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logs
    access_log /var/log/nginx/app.access.log;
    error_log /var/log/nginx/app.error.log;

    # API endpoints with rate limiting
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_conn conn_limit 10;
        
        proxy_pass http://backend;
        proxy_http_version 1.1;
        
        # Proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
    }

    # WebSocket support
    location /ws/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }

    # Static files
    location /static/ {
        alias /var/www/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Angular app
    location / {
        root /var/www/html;
        try_files $uri $uri/ /index.html;
        expires -1;
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0";
    }

    # Health check
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
```

❌ **DON'T:** Expose sensitive information or use weak SSL
```nginx
# Bad: Insecure configuration
server {
    listen 80;
    server_name example.com;
    
    # Bad: No SSL/TLS
    # Bad: No security headers
    # Bad: No rate limiting
    
    location / {
        proxy_pass http://backend;
        # Bad: Missing important headers
    }
    
    # Bad: Exposing server version
    server_tokens on;
    
    # Bad: Directory listing enabled
    autoindex on;
}
```

---

## Security Best Practices

### Environment Security

✅ **DO:** Secure environment management
```bash
# .env.example (committed to repo)
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=your_database
DB_USER=your_user
DB_PASSWORD=your_password

# JWT
JWT_SECRET=your-jwt-secret-min-32-chars
JWT_EXPIRES_IN=1h
JWT_REFRESH_SECRET=your-refresh-secret

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# App
NODE_ENV=development
PORT=3000
API_URL=http://localhost:3000
```

```javascript
// Good: Validate environment variables on startup
const Joi = require('joi');

const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
  PORT: Joi.number().default(3000),
  DB_HOST: Joi.string().required(),
  DB_PORT: Joi.number().required(),
  DB_NAME: Joi.string().required(),
  DB_USER: Joi.string().required(),
  DB_PASSWORD: Joi.string().min(8).required(),
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required()
}).unknown();

const { error, value: envVars } = envSchema.validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

module.exports = envVars;
```

### Dependency Security

✅ **DO:** Keep dependencies updated and scanned
```bash
# Regular security audits
npm audit
npm audit fix

# Use npm-check-updates for updates
npx npm-check-updates -u

# Snyk scanning
npx snyk test
npx snyk monitor

# Lock file integrity
npm ci # Use in CI/CD instead of npm install
```

### CORS Configuration

✅ **DO:** Configure CORS properly
```javascript
// Good: Restrictive CORS
const cors = require('cors');

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
      'https://yourdomain.com',
      'https://www.yourdomain.com'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400, // 24 hours
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
```

❌ **DON'T:** Use wildcard CORS in production
```javascript
// Bad: Allows all origins
app.use(cors()); // Dangerous in production!
```

### SQL Injection Prevention

✅ **DO:** Always use parameterized queries (covered in PostgreSQL section)

### XSS Prevention

✅ **DO:** Sanitize and escape output
```javascript
// Good: Using helmet for security headers
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Sanitize user input
const DOMPurify = require('isomorphic-dompurify');

const sanitizeInput = (input) => {
  return DOMPurify.sanitize(input, { 
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
    ALLOWED_ATTR: []
  });
};
```

### CSRF Protection

✅ **DO:** Implement CSRF tokens
```javascript
// Good: CSRF protection
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csrf({ cookie: true }));

app.get('/form', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Frontend must include token in requests
// Either in headers: X-CSRF-Token
// Or in body: _csrf
```

---

## Code Review Checklist

### Before Submitting PR

- [ ] Code follows project style guide and conventions
- [ ] All tests pass locally
- [ ] New tests added for new functionality
- [ ] No console.log or debug code
- [ ] No commented-out code
- [ ] Environment variables properly configured
- [ ] Error handling implemented
- [ ] Input validation added
- [ ] Security considerations addressed
- [ ] Documentation updated (README, API docs, etc.)
- [ ] No sensitive data in commits
- [ ] Branch is up to date with main/develop
- [ ] Meaningful commit messages

### Reviewer Checklist

**Functionality**
- [ ] Code solves the stated problem
- [ ] Edge cases handled
- [ ] No breaking changes (or properly documented)

**Code Quality**
- [ ] Follows SOLID principles
- [ ] No code duplication
- [ ] Proper separation of concerns
- [ ] Readable and maintainable

**Security**
- [ ] No SQL injection vulnerabilities
- [ ] No XSS vulnerabilities
- [ ] Authentication/authorization properly implemented
- [ ] Sensitive data encrypted
- [ ] Input properly validated

**Performance**
- [ ] No N+1 queries
- [ ] Efficient algorithms used
- [ ] Proper indexing on database queries
- [ ] No memory leaks

**Testing**
- [ ] Unit tests cover critical paths
- [ ] Integration tests for main flows
- [ ] Edge cases tested
- [ ] Test coverage meets requirements (80%+)

**Documentation**
- [ ] Code is self-documenting
- [ ] Complex logic has comments explaining "why"
- [ ] API changes documented
- [ ] README updated if needed

---

## Commit Message Convention

✅ **DO:** Use conventional commits
```
type(scope): subject

body (optional)

footer (optional)

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- style: Code style changes (formatting, etc.)
- refactor: Code refactoring
- test: Adding or updating tests
- chore: Maintenance tasks
- perf: Performance improvements
- ci: CI/CD changes

Examples:
feat(auth): add JWT refresh token rotation
fix(user): resolve email validation bug
docs(api): update authentication endpoints
refactor(database): optimize user queries
test(auth): add integration tests for login flow
```

❌ **DON'T:** Write vague commit messages
```
git commit -m "fix stuff"
git commit -m "updates"
git commit -m "wip"
```

---

## Additional Resources

- **Node.js:** https://nodejs.org/en/docs/
- **Angular:** https://angular.io/docs
- **PostgreSQL:** https://www.postgresql.org/docs/
- **Docker:** https://docs.docker.com/
- **Nginx:** https://nginx.org/en/docs/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **Clean Code:** Robert C. Martin
- **You Don't Know JS:** Kyle Simpson

---

**Remember:** These standards are living documents. As the team and technology evolve, so should these guidelines. Suggest improvements through pull requests!
