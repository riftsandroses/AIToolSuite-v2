import { AlertCircle, Maximize2, Minimize2, ZoomIn, ZoomOut, RotateCcw, Move } from 'lucide-react';
import React, { useState, useEffect, useRef } from 'react';

const MermaidDiagram = ({ chart, id }) => {
    const mermaidRef = useRef(null);
    const containerRef = useRef(null);
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [svgContent, setSvgContent] = useState('');
    const [isFullScreen, setIsFullScreen] = useState(false);
    const [zoom, setZoom] = useState(2); // Default to 200%
    const [pan, setPan] = useState({ x: 0, y: 0 });
    const [isDragging, setIsDragging] = useState(false);
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

    useEffect(() => {
        // Ensure we have a chart
        if (!chart) return;

        let isMounted = true;

        const renderDiagram = async () => {
            if (!isMounted) return;
            setIsLoading(true);
            setError(null);
            setSvgContent(''); // Clear previous content
            // Reset zoom and pan when new chart loads
            setZoom(2); // Default to 200%
            setPan({ x: 0, y: 0 });

            try {
                // Dynamically import the browser-compatible ESM build of Mermaid
                const mermaid = (await import('https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs')).default;

                mermaid.initialize({
                    startOnLoad: false,
                    theme: 'dark',
                    themeVariables: {
                        primaryColor: '#3B82F6',
                        primaryTextColor: '#FFFFFF',
                        primaryBorderColor: '#1F2937',
                        lineColor: '#6B7280',
                        secondaryColor: '#1F2937',
                        tertiaryColor: '#374151',
                        background: '#111827',
                        mainBkg: '#1F2937',
                        secondBkg: '#374151',
                        tertiaryBkg: '#4B5563'
                    },
                    flowchart: {
                        nodeSpacing: 50,
                        rankSpacing: 50,
                        curve: 'basis'
                    }
                });

                // Generate a unique ID for the diagram
                const uniqueId = `mermaid-${id}-${Date.now()}`;

                // The mermaid.render function returns the SVG code
                const { svg } = await mermaid.render(uniqueId, chart);

                if (isMounted) {
                    setSvgContent(svg);
                }
            } catch (err) {
                console.error('Mermaid rendering error:', err);
                if (isMounted) {
                    setError(err.message || 'Invalid Mermaid syntax.');
                }
            } finally {
                if (isMounted) {
                    setIsLoading(false);
                }
            }
        };

        renderDiagram();

        // Cleanup function
        return () => {
            isMounted = false;
        };

    }, [chart, id]);

    // Full screen toggle
    const toggleFullScreen = () => {
        setIsFullScreen(!isFullScreen);
    };

    // Zoom functions
    const zoomIn = () => {
        setZoom(prev => Math.min(prev + 0.2, 20)); // Max zoom 2000%
    };

    const zoomOut = () => {
        setZoom(prev => Math.max(prev - 0.2, 0.2));
    };

    const resetView = () => {
        setZoom(2); // Reset to 200%
        setPan({ x: 0, y: 0 });
    };

    // Mouse wheel zoom
    const handleWheel = (e) => {
        e.preventDefault();
        const delta = e.deltaY > 0 ? -0.1 : 0.1;
        setZoom(prev => Math.min(Math.max(prev + delta, 0.2), 20)); // Max zoom 2000%
    };

    // Pan functionality
    const handleMouseDown = (e) => {
        setIsDragging(true);
        setDragStart({
            x: e.clientX - pan.x,
            y: e.clientY - pan.y
        });
    };

    const handleMouseMove = (e) => {
        if (!isDragging) return;
        setPan({
            x: e.clientX - dragStart.x,
            y: e.clientY - dragStart.y
        });
    };

    const handleMouseUp = () => {
        setIsDragging(false);
    };

    // Touch events for mobile
    const handleTouchStart = (e) => {
        if (e.touches.length === 1) {
            const touch = e.touches[0];
            setIsDragging(true);
            setDragStart({
                x: touch.clientX - pan.x,
                y: touch.clientY - pan.y
            });
        }
    };

    const handleTouchMove = (e) => {
        if (!isDragging || e.touches.length !== 1) return;
        e.preventDefault();
        const touch = e.touches[0];
        setPan({
            x: touch.clientX - dragStart.x,
            y: touch.clientY - dragStart.y
        });
    };

    const handleTouchEnd = () => {
        setIsDragging(false);
    };

    // Escape key to exit full screen
    useEffect(() => {
        const handleEscape = (e) => {
            if (e.key === 'Escape' && isFullScreen) {
                setIsFullScreen(false);
            }
        };

        document.addEventListener('keydown', handleEscape);
        return () => document.removeEventListener('keydown', handleEscape);
    }, [isFullScreen]);

    return (
        <>
            <div
                ref={containerRef}
                className={`
                    bg-gray-900 rounded-lg border border-gray-700 transition-all duration-300
                    ${isFullScreen
                        ? 'fixed inset-0 z-50 rounded-none border-0'
                        : 'relative min-h-[300px]'
                    }
                `}
            >
                {/* Control Panel */}
                <div className="absolute top-4 right-4 z-10 flex gap-2 bg-gray-800/90 backdrop-blur-sm rounded-lg p-2 border border-gray-600">
                    <button
                        onClick={zoomOut}
                        disabled={zoom <= 0.2}
                        className="p-2 text-gray-300 hover:text-white hover:bg-gray-700 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        title="Zoom Out"
                    >
                        <ZoomOut className="w-4 h-4" />
                    </button>

                    <button
                        onClick={zoomIn}
                        disabled={zoom >= 20}
                        className="p-2 text-gray-300 hover:text-white hover:bg-gray-700 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        title="Zoom In"
                    >
                        <ZoomIn className="w-4 h-4" />
                    </button>

                    <button
                        onClick={resetView}
                        className="p-2 text-gray-300 hover:text-white hover:bg-gray-700 rounded transition-colors"
                        title="Reset View"
                    >
                        <RotateCcw className="w-4 h-4" />
                    </button>

                    <div className="w-px bg-gray-600"></div>

                    <button
                        onClick={toggleFullScreen}
                        className="p-2 text-gray-300 hover:text-white hover:bg-gray-700 rounded transition-colors"
                        title={isFullScreen ? "Exit Full Screen" : "Full Screen"}
                    >
                        {isFullScreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                    </button>
                </div>

                {/* Zoom indicator */}
                <div className="absolute top-4 left-4 z-10 bg-gray-800/90 backdrop-blur-sm rounded-lg px-3 py-1 border border-gray-600">
                    <span className="text-sm text-gray-300">{Math.round(zoom * 100)}%</span>
                </div>

                {/* Pan hint */}
                {zoom > 1 && (
                    <div className="absolute bottom-4 left-4 z-10 bg-gray-800/90 backdrop-blur-sm rounded-lg px-3 py-2 border border-gray-600 flex items-center gap-2">
                        <Move className="w-4 h-4 text-gray-400" />
                        <span className="text-xs text-gray-300">Click and drag to pan</span>
                    </div>
                )}

                {/* Main content area */}
                <div className={`relative w-full h-full overflow-hidden ${isFullScreen ? 'h-screen' : 'min-h-[300px]'} flex flex-col justify-center items-center p-4`}>
                    {error && (
                        <div className="w-full max-w-2xl text-red-400 text-center p-4 bg-red-900/20 border border-red-500 rounded-lg">
                            <AlertCircle className="w-8 h-8 mx-auto mb-3" />
                            <h3 className="font-bold text-lg">Diagram Error</h3>
                            <p className="text-sm text-red-300 mt-1">{error}</p>
                            <div className="mt-4 text-left">
                                <h5 className="font-semibold mb-2 text-gray-200">Your Mermaid Code:</h5>
                                <pre className="text-xs text-gray-300 bg-gray-800 p-3 rounded-md overflow-x-auto max-h-32">
                                    <code>{chart}</code>
                                </pre>
                            </div>
                        </div>
                    )}

                    {!error && (
                        <div
                            className="flex justify-center items-center w-full h-full cursor-grab active:cursor-grabbing select-none"
                            aria-live="polite"
                            onWheel={handleWheel}
                            onMouseDown={handleMouseDown}
                            onMouseMove={handleMouseMove}
                            onMouseUp={handleMouseUp}
                            onMouseLeave={handleMouseUp}
                            onTouchStart={handleTouchStart}
                            onTouchMove={handleTouchMove}
                            onTouchEnd={handleTouchEnd}
                            style={{
                                cursor: isDragging ? 'grabbing' : (zoom > 1 ? 'grab' : 'default')
                            }}
                        >
                            {isLoading ? (
                                <div className="text-gray-400 animate-pulse">Loading diagram...</div>
                            ) : svgContent ? (
                                <div
                                    ref={mermaidRef}
                                    className="transition-transform duration-100"
                                    style={{
                                        transform: `scale(${zoom}) translate(${pan.x / zoom}px, ${pan.y / zoom}px)`,
                                        transformOrigin: 'center center'
                                    }}
                                    dangerouslySetInnerHTML={{ __html: svgContent }}
                                />
                            ) : null}
                        </div>
                    )}
                </div>
            </div>

            {/* Full screen overlay backdrop */}
            {isFullScreen && (
                <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40" />
            )}
        </>
    );
};

export default MermaidDiagram;