from flask import Flask, request, redirect, make_response, url_for
from playwright.sync_api import sync_playwright
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
import time
import os
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv

load_dotenv()


def clear_cache():
    global cache
    cache = {}
    print("[INFO] Cache cleared.")


app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app
)

cache = {}

ADMIN_COOKIE = os.getenv("FLAG")


@app.route("/")
def news():
    print(f"[INFO] Request from {request.remote_addr}")
    user_agent = request.headers.get("User-Agent", "default")
    path = request.path
    print(f"[INFO] User-Agent: {user_agent}, Path: {path}")

    template = """
    <html>
    <head>
        <title>Breaking News</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; }
            h1 { color: #333; }
            p { font-size: 18px; }
            a { color: #007bff; text-decoration: none; }
            button { background-color: #007bff; color: white; border: none; padding: 10px 15px; cursor: pointer; }
            button:hover { background-color: #0056b3; }
            .alias { font-size: 14px; color: #777; }
            .container { max-width: 600px; margin: 50px auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1); }
            .success-message { color: green; font-size: 16px; margin-top: 10px; }
        </style>
        <script>
            function fetchNews() {
                fetch('/fetch-news', {
                    method: 'GET',
                    headers: {
                        'X-Host': window.location.host 
                    }
                })
                .then(response => response.text())
                .then(data => {
                    document.getElementById('news-content').innerHTML = data;
                })
                .catch(error => console.error('Error fetching news:', error));
            }
        </script>
    </head>
    <body>
        <div class='container'>
            <h1>Breaking News</h1>
            <button onclick="fetchNews()">Fetch News</button>
            <div id="news-content"></div>
        </div>
    </body>
    </html>
    """

    response = make_response(template)
    response.headers["Cache-Control"] = "no-store, max-age=0" 
    return response


@app.route("/fetch-news")
def fetch_news():
    host = request.headers.get("X-Host", request.host)  
    user_agent = request.headers.get("User-Agent", "default")
    path = request.path
    cache_key = f"{user_agent}:{path}"
    print(f"[INFO] User-Agent: {user_agent}, Path: {path}")

    current_time = time.time()

    if cache_key in cache:
        age = int(current_time - cache[cache_key]["timestamp"])
        cache[cache_key]["age"] = age
        response = make_response(cache[cache_key]["content"])
        response.headers["Cache-Control"] = "public, max-age=5"
        response.headers["Age"] = str(age)
        response.headers["X-Cache-Status"] = "HIT"
        return response

    template = f"""
    <html>
    <head>
        <title>Breaking News</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; }}
            h1 {{ color: #333; }}
            p {{ font-size: 18px; }}
            a {{ color: #007bff; text-decoration: none; }}
            button {{ background-color: #007bff; color: white; border: none; padding: 10px 15px; cursor: pointer; }}
            button:hover {{ background-color: #0056b3; }}
            .alias {{ font-size: 14px; color: #777; }}
            .container {{ max-width: 600px; margin: 50px auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1); }}
            .success-message {{ color: green; font-size: 16px; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class='container'>
            <h1>Breaking News</h1>
            <p>Today's top news: Cybersecurity is cool!</p>
            <p>Second headline: AI is revolutionizing tech!</p>
            <p>Third headline: Python remains the most popular language!</p>
            <p>Fourth headline: Quantum computing makes new strides!</p>
            <p>Fifth headline: SpaceX launches new mission to Mars!</p>
            <p>Sixth headline: Web3 adoption continues to grow!</p>
            <p>Seventh headline: Cloud computing reaches new heights!</p>
            <p>Eighth headline: Open-source contributions hit record levels!</p>
            <p>Ninth headline: Go programming language sees increased usage!</p>
            <p>Tenth headline: Privacy concerns rise with new data laws!</p>
            <p>Eleventh headline: Machine learning models surpass human benchmarks!</p>
            <p>Twelfth headline: Cyber threats evolve with AI-powered attacks!</p>
            <p>Thirteenth headline: 5G networks expand worldwide!</p>
            <p>Fourteenth headline: VR and AR technology redefine gaming!</p>
            <p>Fifteenth headline: Robotics industry experiences major growth!</p>
           <!-- <p>New updates will appear at: <a href='https://{host}'>url</a></p> -->
            <form action='/notify-admin' method='post'>
                <p class='alias'>New news appeared? Notify me and I will check them:</p>
                <input type='hidden' name='url' value='/fetch-news' />
                <button type='submit'>Notify</button>
            </form>
        </div>
    </body>
    </html>
    """

    cache[cache_key] = {"content": template, "timestamp": current_time, "age": 0}

    threading.Timer(5, clear_cache).start()

    response = make_response(template)
    response.headers["X-Original-Host"] = host
    response.headers["Cache-Control"] = "public, max-age=5"
    response.headers["Age"] = "0"
    response.headers["X-Cache-Status"] = "MISS"
    return response


@app.route("/notify-admin", methods=["POST"])
@limiter.limit("1 per 30 seconds")
def notify_admin():
    url = request.form.get("url")
    print(f"[INFO] Notifying admin to visit {url}...")

    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        server_port = app.config.get('SERVER_PORT', 5000)
        url = urljoin(f"http://localhost:{server_port}", url)

    admin_bot_visit(url)
    response = redirect(url_for("notify_success"))
    return response


@app.route("/notify-success")
def notify_success():
    return """
    <html>
    <head>
        <title>Notification Sent</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; }
            .container { max-width: 600px; margin: 50px auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1); }
            h1 { color: green; }
            p { font-size: 18px; }
            a { color: #007bff; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class='container'>
            <h1>Success!</h1>
            <p>The admin has been notified and has checked the news.</p>
            <a href='/'>Go back to News</a>
        </div>
    </body>
    </html>
    """


def admin_bot_visit(url):
    print(f"[BOT] Admin is visiting {url} with Playwright...")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            context.add_cookies([{
                "name": "session",
                "value": ADMIN_COOKIE,
                "url": "http://localhost:5000/",
                "httpOnly": False,
                "secure": False
            }])
            page = context.new_page()
            page.goto(url, timeout=5000)
            cookies = context.cookies()
            print(f"[BOT] Cookies: {cookies}")
            print(f"[BOT] Successfully visited {url}")
            browser.close()
    except Exception as e:
        print(f"[BOT] Error during visit: {e}")
    finally:
        print("[BOT] Done.")


if __name__ == "__main__":
    app.config['SERVER_PORT'] = 5000
    app.run(debug=True, host="0.0.0.0", port=5000)