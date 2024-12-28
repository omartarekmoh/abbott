function showNotification(message, type = 'info', duration = 4000) {
  const notificationContainer = document.getElementById('notification-container');
  
  // If notification exists, clear it first
  clearNotification();

  // Create and display a new notification
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.textContent = message;

  notificationContainer.appendChild(notification);
  notificationContainer.style.display = 'block';

  // Fade out after the specified duration
  if (duration > 0) {
    setTimeout(() => {
      fadeOut(notification);
    }, duration);
  }
}

function fadeOut(element) {
  let opacity = 1; // Initial opacity
  const fadeInterval = setInterval(() => {
    opacity -= 0.05; // Gradually decrease opacity
    if (opacity <= 0) {
      clearInterval(fadeInterval);
      element.remove(); // Remove element after fade-out
      const notificationContainer = document.getElementById('notification-container');
      if (!notificationContainer.firstChild) {
        notificationContainer.style.display = 'none'; // Hide container if no notifications
      }
    } else {
      element.style.opacity = opacity;
    }
  }, 50); // Speed of fading
}

function clearNotification() {
  const notificationContainer = document.getElementById('notification-container');
  notificationContainer.innerHTML = '';
  notificationContainer.style.display = 'none';
}
