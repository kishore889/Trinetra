from fastapi.testclient import TestClient
from app.main import app
from app.services.url_engine import analyze_single_url, analyze_urls_list

client = TestClient(app)

def test_normal_url():
    res = analyze_single_url('https://google.com')
    assert res.url_risk_score < 0.3

def test_ip_url():
    res = analyze_single_url('http://192.168.1.1/login')
    assert res.features.is_ip_hostname is True
    assert res.url_risk_score > 0.5

def test_lookalike_url():
    res = analyze_single_url('https://auth-micros0ft.online/login')
    assert res.features.impersonated_brand == 'microsoft'
    assert res.url_risk_score > 0.7

def test_punycode_url():
    res = analyze_single_url('https://xn--pple-43d.com')
    assert res.features.is_punycode is True

def test_shortener_url():
    res = analyze_single_url('http://bit.ly/12345')
    assert res.features.is_shortener is True

def test_batch_urls():
    res = analyze_urls_list(['https://google.com', 'http://192.168.1.1'])
    assert res.total_urls_analyzed == 2

def test_api_endpoint():
    r = client.post('/api/v1/analyze/url', json={'url': 'http://paypal-fake.info/login'})
    assert r.status_code == 200
    assert r.json()['url_risk_score'] > 0.5
