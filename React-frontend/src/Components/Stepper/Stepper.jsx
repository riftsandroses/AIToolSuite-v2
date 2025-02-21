import { motion } from "framer-motion";
// import { useState } from "react";

const Stepper = ({ steps, section, changeSection }) => {
    return (
        <>
            <div className="w-full flex items-center justify-around space-x-6">
                {["OpenAI Details", "Attacks", "Review"].map((name, i) => (
                    <div className="flex flex-col w-full items-center"
                    // onClick={() => changeSection(i, true)}

                    >
                        <div
                            key={i}
                            className={`${(section < i && "bg-gray-900  h-2 ") ||
                                (section > i && "bg-green-500  h-2") ||
                                "p-0 bg-green-100 dark:bg-green-900"
                                }  w-full rounded flex items-center justify-center transition-bg duration-300 ease-in-out`}

                        >
                            {section === i && (<>
                                <motion.div
                                    className="w-full h-2 rounded flex items-center justify-center bg-green-100 dark:bg-green-900"
                                // layoutId="bg"
                                />

                            </>
                            )}
                        </div>
                        <div className='my-2 text-white font-semibold cursor-pointer'>{name}</div>
                    </div>
                ))}
            </div>
        </>
    )
}

export default Stepper;