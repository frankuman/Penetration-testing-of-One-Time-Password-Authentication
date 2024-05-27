

function sendDATA() {
    // Get the username and password values
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    // Create an object to hold the username and password
    var dataObject = {
        "username": username,
        "password": password
    };

    // Send the data as JSON to the server
    $.ajax({
        url: "/logging", 
        method: "POST",
        dataType: "json",
        data: JSON.stringify(dataObject), // Send serialized form data
        contentType: 'application/json',
        success: function(response) {
            if (response.success) {
                console.log("Login successful");
                window.location.href = "/otp";  // Redirect to "/loggedin" on success
            } else {
                console.error("Login failed: Invalid credentials");
                alert("Login failed. Please check your credentials.");
            }
        },
        error: function(xhr, status, error) {
            console.error("AJAX request failed:", error);
            alert("AJAX request failed. Please try again later.");
        }
    });
}
function verifyCode() {
    var code = document.getElementById("verification_code").value;
    $.ajax({
        url: "/validate",
        method: "POST",
        data: {
            "code": code
        },
        dataType: "json",
        success: function(response) {
            if (response.result === "fail") {
                alert("Failed to validate OTP");
            } else if (response.result === "success") { 
                console.log(response);
                alert("Successfully logged in");
                window.location.href = "/directsuccess";
            } else if (response.result === "wrong") {
                alert("Wrong TOTP");
            } else {
                // Handle unexpected response
                alert("Unexpected response from server");
            }
        },
        error: function(xhr, status, error) {
            console.error("Error triggering challenge:", error);
            alert("Failed to trigger challenge. Please try again.");
        }
    });
}

function logout() {
 
    $.ajax({
        url: "/logout",
        method: "POST",
        dataType: "json",
        success: function(response) {
            // Redirect to login page or perform any other action upon successful logout
            if (response.success) {
                console.log("Logout successful");

                window.location.href = "/";
            }
        },
        error: function(xhr, status, error) {
            console.error("Logout failed:", error);
            alert("Logout failed. Please try again later.");
        }
    });
}