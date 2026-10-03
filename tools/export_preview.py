with open('src/page.h', 'r', encoding='utf-8') as f:
    c = f.read()

start_marker = 'R"HTML('
end_marker = ')HTML";'
start = c.find(start_marker) + len(start_marker)
end = c.rfind(end_marker)
html = c[start:end].strip()

with open('docs/preview.html', 'w', encoding='utf-8') as f:
    f.write(html)

print(f"Generated docs/preview.html ({len(html)} bytes)")
