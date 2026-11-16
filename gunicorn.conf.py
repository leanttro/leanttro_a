import os
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
worker_class = "gthread"
timeout = 60
keepalive = 5
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(L)s'
