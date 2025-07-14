// src/api/dllScannerApi.js

const API_BASE_URL = 'http://localhost:8000/api/v1';

export const connectToScanner = async (connectionData) => {
    const response = await fetch(`${API_BASE_URL}/connect/`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(connectionData)
    });
    if (!response.ok) {
        throw new Error('Failed to connect');
    }
    return response.json();
};

export const initiateProcess = async (appDetails) => {
    const response = await fetch(`${API_BASE_URL}/initiate/`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(appDetails)
    });
    if (!response.ok) {
        throw new Error('Failed to initiate process');
    }
    return response.json();
};

export const filterProcess = async (connectionName) => {
    const response = await fetch(`${API_BASE_URL}/filter_process/`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ connection_name: connectionName })
    });
    if (!response.ok) {
        throw new Error('Failed to filter process');
    }
    return response.json();
};

export const runTester = async (connectionName, id) => {
    const response = await fetch(`${API_BASE_URL}/tester/`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ connection_name: connectionName, id: id })
    });
    if (!response.ok) {
        throw new Error('Failed to run tester');
    }
    return response.json();
};