async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

const processGlucoseData = (latestReading, graphData) => {
  const fullName = `${latestReading.firstName} ${latestReading.lastName}`;
  const currentReading = {
    timestamp: new Date(
      latestReading.glucoseMeasurement.Timestamp
    ).toISOString(),
    glucoseLevel: latestReading.glucoseMeasurement.Value,
  };

  const allReadings = graphData
    ? graphData.map((reading) => ({
        timestamp: new Date(reading.Timestamp).toISOString(),
        glucoseLevel: reading.Value,
      }))
    : [];

  const combinedReadings = [...allReadings, currentReading];
  return { fullName, combinedReadings };
};

class LibreViewClient {
  constructor() {
    this.baseUrl = "https://api.libreview.io";
    this.headers = {
      "accept-encoding": "gzip",
      "cache-control": "no-cache",
      connection: "Keep-Alive",
      "content-type": "application/json",
      product: "llu.android",
      version: "4.12.0",
    };
  }

  async login(email, password) {
    const loginPayload = { email, password };
    const loginUrl = `${this.baseUrl}/llu/auth/login`;

    try {
      let response = await fetch(loginUrl, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(loginPayload),
      });

      let data = await response.json();

      if (data.data?.redirect) {
        this.baseUrl = "https://api-eu.libreview.io";
        const newLoginUrl = `${this.baseUrl}/llu/auth/login`;

        response = await fetch(newLoginUrl, {
          method: "POST",
          headers: this.headers,
          body: JSON.stringify(loginPayload),
        });

        data = await response.json();
      }

      if (!response.ok) {
        throw new Error("Login failed: " + JSON.stringify(data));
      }
 
      this.jwtToken = data.data.authTicket.token;
      this.userId = data.data.user.id;

      this.accountId = await sha256(this.userId);

      this.headers.Authorization = `Bearer ${this.jwtToken}`;
      this.headers["Account-Id"] = this.accountId;

      return data.data;
    } catch (error) {
      throw new Error(`Login error: ${error.message}`);
    }
  }

  async getConnections() {
    try {
      const response = await fetch(`${this.baseUrl}/llu/connections`, {
        headers: this.headers,
      });

      if (!response.ok) {
        throw new Error("Failed to get connections");
      }

      const data = await response.json();
      return data.data;
    } catch (error) {
      throw new Error(`Get connections error: ${error.message}`);
    }
  }

  async getCGMData(patientId) {
    try {
      const response = await fetch(
        `${this.baseUrl}/llu/connections/${patientId}/graph`,
        {
          headers: this.headers,
        }
      );

      if (!response.ok) {
        throw new Error(`Failed to get CGM data (Status: ${response.status})`);
      }

      const data = await response.json();
      return data.data;
    } catch (error) {
      throw new Error(`Get CGM data error: ${error.message}`);
    }
  }
}

async function main() {
  try {
    const client = new LibreViewClient();

    const loginData = await client.login(
      "claudehadd@hotmail.com",
      "Ananas08642!"
    );
    const connectionsData = await client.getConnections();
    if (!connectionsData.length) {
      throw new Error("No connections found");
    }

    const patientId = connectionsData[0].patientId;
    const glucoseMeasurement = connectionsData[0];

    const cgmData = await client.getCGMData(patientId);

    const { fullName: userName, combinedReadings: processedData } =
      processGlucoseData(glucoseMeasurement, cgmData.graphData);

    return processedData;
  } catch (error) {
    console.error("Error:", error.message);
    throw error;
  }
}

// main().catch(console.error);

module.exports = {
    processGlucoseData,
    LibreViewClient,
  };