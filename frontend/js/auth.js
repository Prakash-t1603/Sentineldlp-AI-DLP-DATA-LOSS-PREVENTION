// Authentication Controller
document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  const logoutBtns = document.querySelectorAll(".btn-logout");

  // Check current auth status on protected pages
  const currentPath = window.location.pathname;
  const isAuthPage = currentPath.includes("login") || currentPath === "/" || currentPath.includes("employee-portal");
  const token = API.getToken();

  if (!isAuthPage && !token) {
    window.location.href = "/login";
    return;
  }

  // Populate logged in user badge if present in DOM
  const user = API.getUser();
  const userNameEls = document.querySelectorAll(".current-user-name");
  const userRoleEls = document.querySelectorAll(".current-user-role");

  userNameEls.forEach(el => el.textContent = user.username || "SOC Analyst");
  userRoleEls.forEach(el => el.textContent = (user.role || "Analyst").toUpperCase());

  // Handle Login
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = loginForm.querySelector("button[type='submit']");
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Authenticating...';

      const username_or_email = document.getElementById("login-identity").value.trim();
      const password = document.getElementById("login-password").value;

      try {
        const data = await API.post("/auth/login", { username_or_email, password });
        API.setAuth(data.access_token, data.user);
        showToast("Authentication successful! Redirecting to SOC Dashboard...", "success");
        setTimeout(() => {
          window.location.href = "/dashboard";
        }, 800);
      } catch (err) {
        showToast(err.message || "Invalid credentials", "error");
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-sign-in-alt me-2"></i> Secure Login';
      }
    });
  }

  // Handle Register
  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = registerForm.querySelector("button[type='submit']");
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Creating Account...';

      const username = document.getElementById("reg-username").value.trim();
      const email = document.getElementById("reg-email").value.trim();
      const role = document.getElementById("reg-role").value;
      const password = document.getElementById("reg-password").value;

      try {
        await API.post("/auth/register", { username, email, password, role });
        showToast("Account registered! Logging you in...", "success");
        
        // Auto-login after registration
        const loginData = await API.post("/auth/login", { username_or_email: username, password });
        API.setAuth(loginData.access_token, loginData.user);
        setTimeout(() => {
          window.location.href = "/dashboard";
        }, 1000);
      } catch (err) {
        showToast(err.message || "Registration failed", "error");
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-user-plus me-2"></i> Register Analyst';
      }
    });
  }

  // Handle Logout
  logoutBtns.forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      API.clearAuth();
      showToast("Logged out successfully", "info");
      setTimeout(() => {
        window.location.href = "/login";
      }, 500);
    });
  });
});
