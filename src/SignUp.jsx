import React, { useState } from "react";
import axios from "axios";
import "./index.css";
import { useNavigate } from "react-router-dom";

function SignUp() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    address: "",
    phoneNumber: "",
    email: "",
    password: "",
    confirmPassword: "",
    activities: {
      Acting: "Neither",
      "Tech-Team  (Stage Management, Lights, Sound)": "Neither",
      "Front of House Support  (Ushering, Concessions, Bartending)": "Neither",
      Directing: "Neither",
      "Stagecraft  (Set Building)": "Neither",
      "Production Team": "Neither",
      "Board Member": "Neither",
    },
  });

  const [formErrors, setFormErrors] = useState({});

  const validateField = (name, value) => {
    let error = "";
    switch (name) {
      case "firstName":
        if (!value.trim()) error = "First Name is required.";
        break;
      case "lastName":
        if (!value.trim()) error = "Last Name is required.";
        break;
      case "address":
        if (!value.trim()) error = "Address is required.";
        break;
      case "phoneNumber":
        const phoneRegex = /^[0-9]{10}$/;
        if (!phoneRegex.test(value)) error = "Enter a valid 10-digit phone number.";
        break;
      case "email":
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) error = "Enter a valid email address.";
        break;
      case "password":
        if (value.length < 6) error = "Password must be at least 6 characters long.";
        break;
      case "confirmPassword":
        if (value !== formData.password) error = "Passwords do not match.";
        break;
      default:
        break;
    }
    setFormErrors((prevErrors) => ({
      ...prevErrors,
      [name]: error,
    }));
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
    validateField(name, value);
  };

  const handleActivityChange = (activity, newState) => {
    setFormData((prevData) => ({
      ...prevData,
      activities: {
        ...prevData.activities,
        [activity]: newState,
      },
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Client-side validation
    const errors = {};
    Object.keys(formData).forEach((key) => {
      if (typeof formData[key] === "string") {
        validateField(key, formData[key]);
        if (!formData[key]) {
          errors[key] = `${key} is required.`;
        }
      }
    });

    if (Object.values(errors).some((error) => error)) {
      setFormErrors(errors);
      return;
    }

    try {
      const response = await axios.post("http://localhost:3000/api/register", formData);
      console.log("User registered:", response.data);
      alert("Registration successful!");
      navigate("/checkin");
    } catch (error) {
      console.error("Error registering user:", error.response ? error.response.data : error.message);
      alert("There was an error registering. Please try again.");
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="form-header">
        <h1>Sign Up</h1>
        <span>
          If you are already a member,{" "}
          <a href="/login" className="login-button">
            login
          </a>
        </span>
      </div>
      <div className="form-group">
        <label>
          First Name:
          <input
            type="text"
            name="firstName"
            value={formData.firstName}
            onChange={handleChange}
            placeholder="e.g., John"
            className={formErrors.firstName ? "error" : ""}
          />
        </label>
        {formErrors.firstName && <span className="error-text">{formErrors.firstName}</span>}
      </div>
      <div className="form-group">
        <label>
          Last Name:
          <input
            type="text"
            name="lastName"
            value={formData.lastName}
            onChange={handleChange}
            placeholder="e.g., Doe"
            className={formErrors.lastName ? "error" : ""}
          />
        </label>
        {formErrors.lastName && <span className="error-text">{formErrors.lastName}</span>}
      </div>
      <div className="form-group">
        <label>
          Address:
          <input
            type="text"
            name="address"
            value={formData.address}
            onChange={handleChange}
            placeholder="e.g., 123 Elm St"
            className={formErrors.address ? "error" : ""}
          />
        </label>
        {formErrors.address && <span className="error-text">{formErrors.address}</span>}
      </div>
      <div className="form-group">
        <label>
          Phone Number:
          <input
            type="tel"
            name="phoneNumber"
            value={formData.phoneNumber}
            onChange={handleChange}
            placeholder="e.g., 1234567890"
            className={formErrors.phoneNumber ? "error" : ""}
          />
        </label>
        {formErrors.phoneNumber && <span className="error-text">{formErrors.phoneNumber}</span>}
      </div>
      <div className="form-group">
        <label>
          Email:
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            placeholder="e.g., john.doe@example.com"
            className={formErrors.email ? "error" : ""}
          />
        </label>
        {formErrors.email && <span className="error-text">{formErrors.email}</span>}
      </div>
      <h2>Activities</h2>
      {Object.keys(formData.activities).map((activity) => {
        return (
          <div key={activity} className="activity-row">
            <div className="activity-name">{activity}</div>
            <div className="switch-toggle switch-3 switch-candy">
              <input
                id={`${activity}-neither`}
                name={activity}
                type="radio"
                checked={formData.activities[activity] === "Neither"}
                onChange={() => handleActivityChange(activity, "Neither")}
              />
              <label htmlFor={`${activity}-neither`} className="disabled">
                Neither
              </label>
              <input
                id={`${activity}-interested`}
                name={activity}
                type="radio"
                checked={formData.activities[activity] === "Interested"}
                onChange={() => handleActivityChange(activity, "Interested")}
              />
              <label htmlFor={`${activity}-interested`}>Interested</label>
              <input
                id={`${activity}-participating`}
                name={activity}
                type="radio"
                checked={formData.activities[activity] === "Participating"}
                onChange={() => handleActivityChange(activity, "Participating")}
              />
              <label htmlFor={`${activity}-participating`}>Participating</label>
            </div>
          </div>
        );
      })}
      <div className="form-group">
        <label>
          Password:
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            className={formErrors.password ? "error" : ""}
          />
        </label>
        {formErrors.password && <span className="error-text">{formErrors.password}</span>}
      </div>
      <div className="form-group">
        <label>
          Confirm Password:
          <input
            type="password"
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={handleChange}
            className={formErrors.confirmPassword ? "error" : ""}
          />
        </label>
        {formErrors.confirmPassword && (
          <span className="error-text">{formErrors.confirmPassword}</span>
        )}
      </div>
      <button type="submit" className="submit-button">
        Submit
      </button>
    </form>
  );
}

export default SignUp;
