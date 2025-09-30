from datetime import datetime
from time import time
from wsgiref.simple_server import make_server

class BaseMiddleware:
    def __init__(self, app):  # Constructor
        self.app = app  # Store the next application/middleware
    
    def dispatch(self, request, call_next):  # Method to handle request processing
        raise NotImplementedError  # Make subclasses to implement this method
    
    def __call__(self, environ):  # Make instances callable like WSGI apps
        return self.dispatch(environ, self.app)  # Call dispatch method

class Wyserver:  # Main server class
    def __init__(self):  # Constructor to initialize server
        self.routes = {  # Dictionary to store all routes
            'GET': {  # GET method routes
                '/': (self.home, []),
                '/about': (self.about, []),
                '/contact': (self.contact, []),
                '/inspect': (self.inspect, []),
                '/log-test': (self.log_test, []),
                '/time-test': (self.time_test, []),
                '/secure': (self.secure, []),
                '/footer-test': (self.footer_test, []), 
                '/secure/ping': (self.secure_ping, []),
                '/open/ping': (self.open_ping, [])
            }
        }
        self.middlewares = []  # List to store middleware functions
    
    def add_middleware(self, middleware):
        self.middlewares.append(middleware)  # Add middleware to the list
    
    def app_middleware(self, type_=None):  # Decorator for middleware registration
        def decorator(func):  # Inner function
            self.add_middleware(func)  # Register the function as middleware
            return func  # Return original function 
        return decorator  # Return the decorator
    
    def add_route(self, path, handler, methods=['GET'], middleware=None):  # Add new route
        route_middleware = middleware if middleware else []  # Use provided middleware or empty list
        for method in methods:  # Loop through all specified HTTP methods
            if method not in self.routes:  # Check if method exists in routes
                self.routes[method] = {}  # Create new method dictionary if not exists
            self.routes[method][path] = (handler, route_middleware)  # Store handler and middleware
    
    def __call__(self, environ, start_response):  # WSGI application interface
        method = environ.get('REQUEST_METHOD', 'GET')  # Get HTTP method from request
        path = environ.get('PATH_INFO', '/')  # Get request path
        query_string = environ.get('QUERY_STRING', '')  # Get query string
        user_agent = environ.get('HTTP_USER_AGENT', '')  # Get user agent header
        accept = environ.get('HTTP_ACCEPT', '')  # Get accept header
        
        print(f"REQUEST_METHOD: {method}")  # Print method 
        print(f"PATH_INFO: {path}")  # Print path 
        print(f"QUERY_STRING: {query_string}")  # Print query 
        print(f"HTTP_USER_AGENT: {user_agent}")  # Print user 
        print(f"HTTP_ACCEPT: {accept}")  # Print accept 
        
        timestamp = datetime.now().isoformat()  # Get timestamp
        log_entry = f"[{timestamp}] METHOD: {method} PATH: {path} QUERY: {query_string} headers: User-Agent={user_agent}, Accept={accept}\n"  # Create log entry
        
        with open('logs.txt', 'a') as f:  # Open log file in append mode
            f.write(log_entry)  # Write log entry to file
        
        environ['_wyserver_headers'] = []  # Initialize list for extra headers
        
        if method in self.routes and path in self.routes[method]:  # Check if route exists
            handler, route_middleware = self.routes[method][path]  # Get handler and middleware for route
            
            def base_handler(env):  # Define base handler function
                return handler(env)  # Call the actual route handler
            
            wrapped = base_handler  # Start with base handler
            
            for mw in route_middleware:  # Apply route-specific middleware
                wrapped = self._wrap_middleware(mw, wrapped)  # Wrap handler with middleware
            
            for mw in reversed(self.middlewares):  # Apply global middleware in reverse order
                wrapped = self._wrap_middleware(mw, wrapped)
            
            status, headers, body = wrapped(environ)  # Execute the wrapped handler chain
            
            extra_headers = environ.get('_wyserver_headers', [])  # Get extra headers
            headers = headers + extra_headers  # Combine headers
            
        elif method != 'GET' and path in ['/about', '/contact']:  # Check for method not allowed
            status, headers, body = self.method_not_allowed()  # Return response
        else:  # Route not found
            status, headers, body = self.not_found()  # Return response
        
        start_response(status, headers)  # Start WSGI response
        return [body.encode('utf-8')]  # Return response body
    
    def _wrap_middleware(self, middleware, next_handler):  # wrap middleware
        if isinstance(middleware, type) and issubclass(middleware, BaseMiddleware):  # Check if class-based middleware
            def wrapper(env):
                mw_instance = middleware(next_handler)  # Create middleware instance
                return mw_instance(env)  # Call
            return wrapper  
        else:  # Function-based middleware
            def wrapper(env): 
                return middleware(env, next_handler)  # Call middleware function
            return wrapper 
    
    def home(self, environ):  # Home page handler
        body = "<h1>Home Page</h1><p>Welcome to my website</p>" 
        headers = [ 
            ('Content-Type', 'text/html'), 
            ('Content-Length', str(len(body))) 
        ]
        return '200 OK', headers, body  
    
    def about(self, environ):  # About page handler
        body = "<h1>About</h1><p>I dont know what to put here</p>"  
        headers = [ 
            ('Content-Type', 'text/html'), 
            ('Content-Length', str(len(body))) 
        ]
        return '200 OK', headers, body  
    
    def contact(self, environ):  # Contact page handler
        body = "<h1>Contact Us</h1><p>I dont know what to put here too</p>" 
        headers = [ 
            ('Content-Type', 'text/html'), 
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body  
    
    def inspect(self, environ):  # Request inspection handler
        headers_html = ""  # Initialize headers HTML
        for key, value in environ.items():  # Loop through all environment variables
            if key.startswith('HTTP_'):  # Check if it's an HTTP header
                headers_html += f"<tr><td>{key}</td><td>{value}</td></tr>"  # Add to headers table
        
        query_params = {}  # Initialize query parameters dict
        query_string = environ.get('QUERY_STRING', '')  # Get query string
        if query_string:  # Check if query string exists
            for param in query_string.split('&'):  # Split query string by &
                if '=' in param:  # Check if parameter has value
                    key, value = param.split('=', 1)  # Split key and value
                    query_params[key] = value  # Store in dict
        
        query_html = ""  # Initialize query HTML
        for key, value in query_params.items():  # Loop through query parameters
            query_html += f"<tr><td>{key}</td><td>{value}</td></tr>"  # Add to query table
        
        body = f"""  # Create response body with formatted HTML
        <html>
        <head><title>Request Inspection</title></head>
        <body>
            <h1>Request Headers</h1>
            <table border="1">{headers_html}</table>
            <h1>Query Parameters</h1>
            <table border="1">{query_html}</table>
        </body>
        </html>
        """
        headers = [ 
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body  
    
    def log_test(self, environ):  # Log test handler
        body = "<h1>Log Test</h1><p>Check console for logs</p>" 
        headers = [ 
            ('Content-Type', 'text/html'), 
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body 
    
    def time_test(self, environ):  # Time test handler
        body = "<h1>Time Test</h1><p>Check X-Process-Time header</p>" 
        headers = [  
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body  
    
    def secure(self, environ):  # Secure page handler
        body = "<h1>Secure Page</h1><p>You are authorized!</p>"  
        headers = [  
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body  
    
    def footer_test(self, environ):  # Footer test handler
        body = "<h1>Footer Test</h1><p>This page has a footer comment</p>"  
        headers = [  
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body  
    
    def secure_ping(self, environ):  # Secure ping handler
        body = "<h1>Secure Ping</h1><p>Authorization required</p>"  
        headers = [  
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body  
    
    def open_ping(self, environ):  # Open ping handler
        body = "<h1>Open Ping</h1><p>No authorization needed</p>"  
        headers = [  
            ('Content-Type', 'text/html'), 
            ('Content-Length', str(len(body)))  
        ]
        return '200 OK', headers, body  
    
    def not_found(self):  # 404 handler
        body = "<h1>404 Not Found</h1><p>The page you requested does not exist.</p>"  
        headers = [  
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body)))  
        ]
        return '404 Not Found', headers, body  
    
    def method_not_allowed(self):  # 405 handler
        body = "<h1>405 Method Not Allowed</h1><p>This method is not allowed for this resource.</p>" 
        headers = [  
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body))),  
            ('Allow', 'GET')  
        ]
        return '405 Method Not Allowed', headers, body  

def logging_middleware(environ, call_next):  # Logging middleware function
    path = environ.get('PATH_INFO', '/')  # Get request path
    print(f"[LOGGING] Before: {path}")  # Log before processing
    status, headers, body = call_next(environ)  # Call next middleware/handler
    print(f"[LOGGING] After: {path}")  # Log after processing
    return status, headers, body  

def timing_middleware(environ, call_next):  # Timing middleware function
    start = time()  # Get start time
    status, headers, body = call_next(environ)  # Call next middleware/handler
    duration = time() - start  # Calculate duration
    environ.setdefault('_wyserver_headers', []).append(('X-Process-Time', f"{duration:.4f}"))  # Add timing header
    return status, headers, body  

def authorization_middleware(environ, call_next):  # Authorization middleware function
    auth = environ.get('HTTP_AUTHORIZATION', '')  # Get authorization header
    if not auth or auth != 'valid-token-123':  # Check if valid token
        body = "<h1>401 Unauthorized</h1><p>Invalid or missing token</p>"  
        headers = [  
            ('Content-Type', 'text/html'),  
            ('Content-Length', str(len(body)))  
        ]
        return '401 Unauthorized', headers, body 
    return call_next(environ)  

def footer_middleware(environ, call_next):  # Footer middleware function
    status, headers, body = call_next(environ)  # Call next middleware/handler
    content_type = next((v for k, v in headers if k == 'Content-Type'), '')  # Get content type
    if 'text/html' in content_type or 'text/plain' in content_type:  # Check if text content
        body += "\n<!-- Generated by Wyserver -->"  # Add footer comment
        headers = [(k, v) if k != 'Content-Length' else (k, str(len(body))) for k, v in headers]  # Update content length
    return status, headers, body  # Return modified response

class AuthMiddleware(BaseMiddleware):  # Class-based auth middleware
    def dispatch(self, environ, call_next):  # Implement dispatch method
        auth = environ.get('HTTP_AUTHORIZATION', '')  # Get authorization header
        if not auth or auth != 'valid-token-123':  # Check if valid token
            body = "<h1>401 Unauthorized</h1><p>Invalid or missing token</p>" 
            headers = [ 
                ('Content-Type', 'text/html'), 
                ('Content-Length', str(len(body))) 
            ]
            return '401 Unauthorized', headers, body  
        return call_next(environ)  # Continue if authorized

app = Wyserver()

app.add_middleware(logging_middleware)  # Add logging middleware
app.add_middleware(timing_middleware)  # Add timing middleware
app.add_middleware(footer_middleware)  # Add footer middleware

app.add_route('/secure/ping', app.secure_ping, methods=['GET'], middleware=[authorization_middleware])  # Add secure route with auth
app.add_route('/open/ping', app.open_ping, methods=['GET'])  # Add open route

@app.app_middleware()  # Register middleware using decorator
def custom_middleware(environ, call_next):  # Custom middleware function
    print("[CUSTOM] Middleware decorator works!")  # Print debug message
    return call_next(environ)  # Continue to next handler

if __name__ == '__main__':
    port = 8000  
    with make_server('', port, app) as httpd:  
        print(f"Server running on http://localhost:{port}") 
        print("Available routes:")  
        print("  GET /")  
        print("  GET /about")  
        print("  GET /contact")  
        print("  GET /inspect")  
        print("  GET /log-test")  
        print("  GET /time-test")  
        print("  GET /secure/ping (requires Authorization header)")  
        print("  GET /open/ping") 
        print("  GET /footer-test") 
        httpd.serve_forever() 


#curl http://localhost:8000/
#curl http://localhost:8000/about
#curl http://localhost:8000/contact
#curl "http://localhost:8000/inspect?name=test&value=123"
#curl -v http://localhost:8000/time-test
#curl http://localhost:8000/secure/ping
#curl -H "Authorization: valid-token-123" http://localhost:8000/secure/ping
#curl http://localhost:8000/open/ping
#curl http://localhost:8000/footer-test