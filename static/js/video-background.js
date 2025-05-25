document.addEventListener('DOMContentLoaded', function() {
    const video = document.getElementById('video-background');
    
    // Start loading the video immediately
    video.load();
    
    // Show video when it's ready to play
    video.addEventListener('canplay', function() {
        video.classList.add('loaded');
    });

    // Handle video loading errors
    video.addEventListener('error', function() {
        console.error('Error loading video');
        document.querySelector('.video-placeholder').style.opacity = '1';
    });

    // Optimize video loading
    video.addEventListener('loadeddata', function() {
        video.play().catch(function(error) {
            console.log("Video autoplay failed:", error);
        });
    });
}); 