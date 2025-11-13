from app import app

with app.test_client() as client:
    resp = client.post('/login', data={'username': 'drivenbyfaith3d', 'password': 'Sue5743pond!'}, follow_redirects=True)
    print('login status', resp.status_code)
    resp = client.post('/quote', data={'quote_type': 'needs_design', 'requester_name': 'Test', 'notes': 'hi'}, follow_redirects=True)
    print('quote status', resp.status_code)
    print(resp.data[:200])
