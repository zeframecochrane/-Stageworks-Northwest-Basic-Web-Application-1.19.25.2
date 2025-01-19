import React, { useContext } from 'react';
import { Link } from 'react-router-dom';
import { AuthContext } from './AuthContext';

function App() {
  const { isAuthenticated } = useContext(AuthContext);

  return (
    <div>
      <header className="header">
        <div className="navbar">
          <img 
            src="https://static.wixstatic.com/media/7e1f44_2fc0b74f7c7e473faaca069320a3d94f~mv2.png/v1/crop/x_0,y_7,w_1041,h_221/fill/w_424,h_85,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/swnw%20logo%20white%20font.png" 
            alt="Stageworks Logo" 
            className="h-10" 
            style={{ width: '424px', height: '85px', objectFit: 'cover' }} 
          />
          <nav>
            <Link to="/">Home</Link>
            <Link to="/signup" className="ml-4">Sign Up</Link>
            <Link to="/login" className="ml-4">Login</Link>
            {isAuthenticated && (
              <>
                <Link to="/checkin" className="ml-4">Check-in</Link>
                <span className="ml-4 text-green-500">Logged In</span>
              </>
            )}
          </nav>
        </div>
      </header>
      <main>
        <div className="marquee-banner">
          <h1>Welcome to the Volunteer Tracking App</h1>
        </div>
        <section className="section">
          <h2>Introduction</h2>
          <p>Welcome to the Stageworks Northwest Volunteer Logging App. This app helps measure the wonderful work you do seamlessly.</p>
          <div className="section-divider"></div>
          <h2>Quick Links</h2>
          {isAuthenticated && (
            <Link to="/checkin" className="button">Check In</Link>
          )}
          <Link to="/signup" className="button">Sign Up</Link>
        </section>
      </main>
      <footer className="footer">
        <img 
          src="https://static.wixstatic.com/media/7e1f44_2fc0b74f7c7e473faaca069320a3d94f~mv2.png/v1/crop/x_0,y_7,w_1041,h_221/fill/w_424,h_85,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/swnw%20logo%20white%20font.png" 
          alt="Stageworks Logo" 
          className="h-10" 
          style={{ width: '424px', height: '85px', objectFit: 'cover' }} 
        />
        <p>Contact us at info@stageworksnw.org</p>
        <p>Follow us on social media</p>
      </footer>
    </div>
  );
}

export default App;
