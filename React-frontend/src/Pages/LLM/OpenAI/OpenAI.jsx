import React, { useState } from 'react'
// import Input from "../../../Components/Input/Input";
// import Textarea from '../../../Components/Textarea/Textarea';
// import Dropdown from '../../../Components/Dropdown/Dropdown';
import Stepper from '../../../Components/Stepper/Stepper';

// import { motion } from "framer-motion";
// import AutoHeight from "react-auto-height";
// import { HiOutlineArrowLeft } from "react-icons/hi";
import FormOpenAI from './FormOpenAI';
import classes from "./openAI.module.css"

const OpenAI = () => {
    const [openAIData, setOpenAIData] = useState({
        generator: "",
        scanName: "",
        modelName: "",
        clientName: "",
        clientAppName: "",
        apiKey: "",
        description: "",
    })

    console.log(openAIData)

    // Stepper
    const [section, setSection] = useState(0);
    const [isBack, setIsBack] = useState(false);
    const changeSection = (i, isBack) => {
        isBack ? setIsBack(true) : setIsBack(false);
        setSection(i);
    };

    // form
    const handleChange = (keyName, keyValue) => {
        setOpenAIData({
            ...openAIData,
            [keyName]: keyValue
        })
    }



    return (
        <>
            <div className="flex justify-center items-center border w-[100vw] h-[200vh] bg-[#0E0C15] ">
                <div className="flex flex-col w-[50.5rem] bg-[#21242D] p-[1.875rem] rounded-2xl">

                    <div className='flex justify-center items-center w-full pb-4 mb-2 mt-4 border-b-2 border-b-[#ffffff31]'>
                        {/* //Stepper */}
                        <Stepper section={section} changeSection={changeSection} />
                    </div>



                    {section === 0 &&
                        <FormOpenAI isBack={isBack} openAIData={openAIData} handleChange={handleChange} />
                    }

                    {section === 1 &&
                        <FormOpenAI isBack={isBack} openAIData={openAIData} handleChange={handleChange} />
                    }

                    {section === 2 &&
                        <FormOpenAI isBack={isBack} openAIData={openAIData} handleChange={handleChange} />
                    }


                    <div className='flex justify-between mt-8 mb-4'>
                        {/* {section !== 0 && ( */}
                        <button
                            onClick={() => changeSection(section - 1, true)}
                            className={`${classes.btn} ${section === 0 ? "cursor-not-allowed opacity-50" : classes.btnHover}`}
                            disabled={section === 0 ? true : false}
                        >
                            Back
                        </button>
                        {section === 2 ?
                            <>
                                <button
                                    onClick={() => {
                                        changeSection(section + 1, false)
                                    }}
                                    className={`${classes.btn} ${classes.btnHover}`}
                                >
                                    Start Scan
                                </button>
                            </> :
                            <>
                                <button
                                    onClick={() => {
                                        changeSection(section + 1, false)
                                    }}
                                    className={`${classes.btn} ${classes.btnHover}`}
                                >
                                    Continue
                                </button>
                            </>
                        }

                    </div>

                </div>

            </div>
        </>
    )
}

export default OpenAI;





