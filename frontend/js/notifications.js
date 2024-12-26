function showNotification(message, type = "success") {
    const notification = document.getElementById("notification");
    notification.innerText = message;
    notification.className = `notification ${type}`;
    notification.style.display = "block";
  
    setTimeout(() => {
      notification.style.display = "none";
    }, 3000);
  }
  