from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

server = ThreadingHTTPServer(('127.0.0.1', 8080), SimpleHTTPRequestHandler)
print('Local demo server listening on 127.0.0.1:8080')
server.serve_forever()
