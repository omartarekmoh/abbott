const API_URL = "http://localhost:9090";

async function loginUser(email, password) {
  try {
    const response = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) throw new Error("Login failed");

    const data = await response.json();
    showNotification("Login successful!", "success");
    localStorage.setItem("token", data.token); // Store token if needed
    window.location.href = "/dashboard.html"; // Redirect to dashboard
  } catch (error) {
    showNotification("Login failed. Please check your credentials.", "error");
  }
}

async function registerUser(name, email, password) {
  try {
    const response = await fetch(`${API_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password }),
    });

    if (!response.ok) throw new Error("Registration failed");

    showNotification(
      "Registration successful! Check your email for verification.",
      "success"
    );
    window.location.href = "/index.html";
  } catch (error) {
    showNotification(`Registration failed. Please try again. ${error}`, "error");
  }
}

async function verifyEmail(token) {
  try {
    const response = await fetch(`${API_URL}/verify/${token}`);
    console.log(response)
    if (!response.ok) throw new Error("Verification failed");

    showNotification("Email verified successfully!", "success");
    return await response.json();
  } catch (error) {
    showNotification("Email verification failed.", "error");
    throw error;
  }
}
