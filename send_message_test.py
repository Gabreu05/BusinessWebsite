from app import app, db, QuoteRequest

with app.test_client() as client:
    client.post('/login', data={'username': 'drivenbyfaith3d', 'password': 'Sue5743pond!'}, follow_redirects=True)
    resp = client.post('/admin/quotes/5/messages', data={'subject': 'Test', 'body': 'Hello'}, follow_redirects=True)
    print('status', resp.status_code)
    print(resp.data[:200])
