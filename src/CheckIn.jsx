import React, { useEffect, useState, useContext } from 'react';
import QRCode from 'qrcode';
import { AuthContext } from './AuthContext';

const mockDatabase = []; // Mock database for storing QR code details

function CheckIn() {
  const { userData } = useContext(AuthContext);
  const [qrCodeData, setQrCodeData] = useState('');
  const [incompleteCheckOut, setIncompleteCheckOut] = useState(false);
  const [endTime, setEndTime] = useState('');

  useEffect(() => {
    const checkIncompleteSessions = () => {
      const incompleteSession = mockDatabase.find(session => session.email === userData.email && !session.checkedOut);
      if (incompleteSession) {
        setIncompleteCheckOut(true);
      }
    };

    checkIncompleteSessions();
  }, [userData]);

  const generateQRCode = async () => {
    if (!userData) {
      console.error('User data is not available.');
      return;
    }

    const data = {
      firstName: userData.firstName,
      lastName: userData.lastName,
      email: userData.email,
      phoneNumber: userData.phoneNumber,
      timestamp: new Date().toISOString(),
      status: 'Check-in',
    };

    try {
      const qrCodeData = await QRCode.toDataURL(JSON.stringify(data));
      setQrCodeData(qrCodeData);
      mockDatabase.push({ ...data, checkedOut: false });
    } catch (err) {
      console.error('QR Code generation failed:', err);
    }
  };

  const handleCheckOut = () => {
    const session = mockDatabase.find(session => session.email === userData.email && !session.checkedOut);
    if (session) {
      session.checkedOut = true;
      session.endTime = endTime;
    }
    setIncompleteCheckOut(false);
    generateQRCode(); // Generate new QR code after check-out
  };

  return (
    <div className="checkin-container">
      <h1>Check In</h1>
      {incompleteCheckOut ? (
        <div>
          <p>You have an incomplete check-out. Please enter the end time for your previous session:</p>
          <input 
            type="datetime-local" 
            value={endTime} 
            onChange={(e) => setEndTime(e.target.value)} 
          />
          <button onClick={handleCheckOut}>Complete Check-Out</button>
        </div>
      ) : (
        <div>
          <button onClick={generateQRCode}>Generate QR Code</button>
          {qrCodeData && <img src={qrCodeData} alt="QR Code" />}
        </div>
      )}
    </div>
  );
}

export default CheckIn;
