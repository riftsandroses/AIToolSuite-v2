import { useState, useEffect } from 'react';
import { Link, useNavigate, Outlet } from 'react-router-dom';
import { Search, Users, Smartphone, Eye, ArrowLeft, RefreshCw } from 'lucide-react';
import { getAuthCookies } from '../../api/auth';

const baseUrl = process.env.REACT_APP_API_BASE_URL;

const ThreatModelScansTable = ({ scans, onScanClick }) => {

    return (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
                <table className="w-full">
                    <thead>
                        <tr className="bg-gray-700 border-b border-gray-600">
                            <th className="text-left p-4 text-gray-300 font-medium">Scan ID</th>
                            <th className="text-left p-4 text-gray-300 font-medium">Assessment Name</th>
                            <th className="text-left p-4 text-gray-300 font-medium">Client</th>
                            <th className="text-left p-4 text-gray-300 font-medium">Application</th>
                            <th className="text-left p-4 text-gray-300 font-medium">Status</th>
                            <th className="text-left p-4 text-gray-300 font-medium">View</th>
                        </tr>
                    </thead>
                    <tbody>
                        {scans.map((scan) => (
                            <tr
                                key={scan.id}
                                className="border-b border-gray-700 hover:bg-gray-700 transition-colors cursor-pointer"
                                onClick={() => onScanClick(scan.id)}
                            >
                                <td className="p-4 text-gray-300">
                                    <div className="flex items-center gap-2">
                                        <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                                        <span>#{scan.id}</span>
                                    </div>
                                </td>
                                <td className="p-4 text-white font-medium">
                                    <div className="truncate max-w-xs">{scan.assessment_name}</div>
                                </td>
                                <td className="p-4 text-gray-300">
                                    <div className="flex items-center gap-2">
                                        <Users size={16} className="text-blue-400" />
                                        <span className="truncate max-w-xs">{scan.client_name}</span>
                                    </div>
                                </td>
                                <td className="p-4 text-gray-300">
                                    <div className="flex items-center gap-2">
                                        <Smartphone size={16} className="text-green-400" />
                                        <span className="truncate max-w-xs">{scan.app_name}</span>
                                    </div>
                                </td>
                                <td className="p-4">
                                    <div className="bg-blue-600 text-white px-2 py-1 rounded text-xs font-medium inline-block">
                                        {scan.status}
                                    </div>
                                </td>
                                <td className="p-4">
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onScanClick(scan.id);
                                        }}
                                        className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition-colors"
                                    >
                                        <Eye size={14} />
                                        View
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

const AllThreatModelPage = () => {
    const navigate = useNavigate();
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        fetchAllScans();
    }, []);

    const fetchAllScans = async () => {
        setLoading(true);
        const token = getAuthCookies().accessToken;
        try {
            const response = await fetch(`${baseUrl}/api/v1/threat-model/assessments/`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setScans(data);
            } else {
                console.error('Failed to fetch scans');
            }
        } catch (error) {
            console.error('Error fetching scans:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleScanClick = (scanId) => {
        navigate(`/threat-model/${scanId}`);
    };

    const handleRefresh = () => {
        fetchAllScans();
    };

    // Filter scans based on search term
    const filteredScans = scans.filter(scan =>
        scan.assessment_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        scan.client_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        scan.app_name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="min-h-screen bg-gray-900 text-white">
            <div className="max-w-7xl mx-auto p-6">
                {/* Header */}
                <div className="mb-6 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link to="/threat-model" className="text-blue-400 hover:underline flex items-center gap-2">
                            <ArrowLeft size={20} />
                            Back
                        </Link>
                    </div>
                    <button
                        onClick={handleRefresh}
                        className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
                    >
                        <RefreshCw size={16} />
                        Refresh
                    </button>
                </div>

                <div className="mb-8">
                    <h1 className="text-4xl font-bold text-blue-300 mb-2">Threat Model Scans Management</h1>
                    <p className="text-lg text-gray-400">
                        Comprehensive overview of all threat model scans
                    </p>
                </div>

                {/* Search Control */}
                <div className="bg-gray-800 rounded-lg p-6 mb-6">
                    <div className="relative">
                        <Search className="absolute left-3 top-3 text-gray-400" size={20} />
                        <input
                            type="text"
                            placeholder="Search scans by name, client, or application..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full bg-gray-700 border border-gray-600 rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                    </div>
                </div>

                {/* Scans Table */}
                {loading ? (
                    <div className="bg-gray-800 rounded-lg p-12 text-center">
                        <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400 mb-4"></div>
                        <div className="text-gray-400 text-lg">Loading scans...</div>
                    </div>
                ) : filteredScans.length === 0 ? (
                    <div className="bg-gray-800 rounded-lg p-12 text-center">
                        <div className="text-gray-400 text-lg mb-4">
                            {searchTerm ? 'No scans found matching your search.' : 'No scans available.'}
                        </div>
                        {!searchTerm && (
                            <Link
                                to="/threat-model"
                                className="inline-block bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg transition-colors"
                            >
                                Create Your First Scan
                            </Link>
                        )}
                    </div>
                ) : (
                    <div className="space-y-4">
                        {/* Results Header */}
                        <div className="bg-gray-800 rounded-lg p-4">
                            <div className="flex items-center justify-between">
                                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                                    <Search /> List of Scans
                                </h2>
                                <div className="text-sm text-gray-400">
                                    {filteredScans.length} scan{filteredScans.length !== 1 ? 's' : ''} found
                                </div>
                            </div>
                        </div>

                        {/* Table */}
                        <ThreatModelScansTable scans={filteredScans} onScanClick={handleScanClick} />
                    </div>
                )}

                {/* Footer */}
                <div className="mt-8 text-center">
                    <Link
                        to="/threat-model"
                        className="inline-block bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg transition-colors font-medium"
                    >
                        Create New Scan
                    </Link>
                </div>
            </div>
            <Outlet />
        </div>
    );
};

export default AllThreatModelPage;