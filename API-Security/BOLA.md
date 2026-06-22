# OWASP API1:2023 — Broken Object Level Authorization (BOLA)

## What is BOLA
Broken Object Level Authorization is one of the most 
common and dangerous API vulnerabilities. It occurs 
when an API endpoint accepts an object reference — 
such as an ID in the URL path, query string, or 
request body — and returns the requested resource 
without verifying that the requesting user is 
authorized to access it.

## What Are APIs and Why Are They Everywhere
Modern applications are built API-first. A single API 
backend can power a web UI, mobile app, third-party 
integrations, and partner services simultaneously. 
This architecture reduces development overhead but 
significantly increases attack surface — every client 
that consumes the API is a potential attacker entry point.

## Why APIs Are More Exposed Than Traditional Web Apps
In traditional web apps, object references are often 
hidden in server-side session state. The UI controls 
the flow and IDs are not always visible to the user.

In APIs, every resource reference is explicit in the 
request. Endpoints are documented, predictable, and 
designed to be called directly by any client. This 
means:

- IDs are always visible and manipulable
- Endpoints can be called without a UI
- Attackers can automate enumeration at scale
- More clients consuming the API means more 
  potential attackers

## The Authentication Middleware
```python
def logged_in_user_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({
                'status': "error",
                'message': "Authorization token is required in Bearer <token>"
            }), 401
        try:
            if not " " in auth_header:
                return jsonify({
                    'status': "error",
                    'message': "Invalid token format: Bearer <token>"
                }), 401
            token_type, token_string = auth_header.split(" ", maxsplit=1)
            if token_type.lower() != "bearer":
                return jsonify({
                    'status': "error",
                    'message': "Invalid token format: Bearer <token>"
                }), 401
            decoded_payload = jwt.decode(token_string, key=jwt_secret_key, algorithms=['HS256'])
            g.current_user_id = decoded_payload.get('id')
        except jwt.ExpiredSignatureError:
            return jsonify({
                'status': "error",
                'message': "Token expired."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'status': "error",
                'message': "Token invalid"
            }), 401
        return f(*args, **kwargs)
    return wrapper
```


## Vulnerable Code Pattern
The following endpoint fetches an order by ID with 
no ownership check:

```python
@app.route("/api/v1/order/<int:order_id>", methods=["GET"])
@logged_in_user_required
def get_user_order(order_id):
    user_order = db.session.get(Order, order_id)
    if not user_order:
        return jsonify({
            'status': "error",
            'message': "No order found"
        }), 404
    user_order_details = {
        'name': user_order.name,
        'price': user_order.price,
        'status': user_order.status
    }
    return jsonify({
        'status': "success",
        'data': user_order_details
    }), 200
```

The decorator confirms the user is authenticated. 
But authentication is not authorization. Any 
authenticated user can access any order by 
changing the order_id.

## Attack Scenario
Given the endpoint: GET /api/v1/order/{order_id}

An attacker authenticates with their own account 
and observes their order ID in the response:
`GET /api/v1/order/10001 200 Ok` 
They then enumerate adjacent IDS (for other users):
`GET /api/v1/order/10002`
`GET /api/v1/order/10003`

The API returns other users' order details — names, 
prices, statuses — with no authorization check. 
At scale this becomes a full data breach automated 
with a simple loop.

## Secure Code Pattern
The fix requires one explicit ownership check after 
fetching the object:

```python
@app.route("/api/v1/order/<int:order_id>", methods=["GET"])
@logged_in_user_required
def get_user_order(order_id):
    user_order = db.session.get(Order, order_id)
    if not user_order:
        return jsonify({
            'status': "error",
            'message': "No order found"
        }), 404
    # Ownership check — this is the BOLA fix
    if user_order.user_id != g.current_user_id:
        return jsonify({
            'status': "error",
            'message': "You don't have permission to access this resource"
        }), 403
    user_order_details = {
        'name': user_order.name,
        'price': user_order.price,
        'status': user_order.status
    }
    return jsonify({
        'status': "success",
        'data': user_order_details
    }), 200
```

`g.current_user_id` is extracted from the JWT 
inside the `logged_in_user_required` decorator 
and made available to the route via Flask's 
request-scoped `g` object.

The critical line is:
```python
if user_order.user_id != g.current_user_id:
```

Never trust the ID in the URL. Always verify 
ownership against the authenticated identity.

## The 403 vs 404 Tradeoff
While implementing the ownership check, an 
interesting question arises: should an unauthorized 
request return 403 or 404?

- **403 Forbidden** — semantically correct. The 
  resource exists but you are not authorized.
- **404 Not Found** — hides whether the resource 
  exists at all.

Returning 403 for unauthorized resources leaks 
existence information. An attacker enumerating IDs 
can distinguish between resources that exist and 
resources that do not:

`GET /api/v1/order/1001  →  403  (exists, not yours)`
`GET /api/v1/order/1002  →  403  (exists, not yours)`
`GET /api/v1/order/1003  →  404  (does not exist)`
`GET /api/v1/order/1004  →  403  (exists, not yours)`
This is the same principle behind username 
enumeration via forgotten password functionality — 
different responses reveal the state of a resource.

Some APIs return 404 for all unauthorized resources 
to prevent enumeration. This is called resource 
existence concealment. The tradeoff is that it 
breaks HTTP semantic correctness and makes 
debugging harder for developers.

The right choice depends on your threat model. 
High sensitivity APIs should consider returning 
404 universally for unauthorized access.

## Remediation Checklist
- Never rely on client-supplied IDs alone to 
  fetch objects
- Always verify the authenticated user owns or 
  has access to the requested object
- Implement ownership checks at the data layer, 
  not just the route level
- Avoid sequential integer IDs — use GUIDs to 
  make enumeration harder
- Apply the principle of least privilege — users 
  should only access what they explicitly need
- Consider resource existence concealment for 
  high sensitivity endpoints

## References
- OWASP API Security Top 10: API1:2023
- APIsec University — OWASP API Top 10 and Beyond
- PortSwigger Web Security Academy — Access Control
