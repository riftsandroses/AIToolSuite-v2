import React from 'react'
import Input from "../../../Components/Input/Input";
import Textarea from '../../../Components/Textarea/Textarea';
import { motion } from "framer-motion";
import Dropdown from '../../../Components/Dropdown/Dropdown';

const FormOpenAI = ({ isBack, openAIData, handleChange }) => {
    return (
        <>
            <motion.div
                style={isBack ? { x: -200, opacity: 0 } : { x: 200, opacity: 0 }}
                animate={
                    isBack
                        ? { translateX: 200, opacity: 1 }
                        : { translateX: -200, opacity: 1 }
                }
                className='inputContainer'
            >
                <div className='flex justify-between my-4'>
                    <InputComponent
                        label={"scanName"}
                        placeholder={"Scan Name"}
                        value={openAIData.scanName}
                        handleChange={handleChange}
                        width={"100%"}
                    />
                </div>

                <div className='flex justify-between my-4'>
                    <InputComponent
                        label={"clientName"}
                        placeholder={"Client Name"}
                        value={openAIData.clientName}
                        handleChange={handleChange}
                        width={"46%"}
                    />
                    <InputComponent
                        label={"clientAppName"}
                        placeholder={"Client App Name"}
                        value={openAIData.clientAppName}
                        handleChange={handleChange}
                        width={"46%"}
                    />
                </div>

                <div className='flex justify-between my-4'>
                    <DropdownComponent
                        label={"modelName"}
                        options={dropdownOptions}
                        placeholder={"Model Name"}
                        value={openAIData.modelName}
                        handleChange={handleChange}
                        width={"100%"}
                    />
                </div>

                <div className='flex justify-between my-4'>
                    <InputComponent
                        label={"apiKey"}
                        placeholder={"API Key"}
                        value={openAIData.apiKey}
                        handleChange={handleChange}
                        width={"100%"}
                    />
                </div>

                <div className='flex justify-between my-4'>
                    <TextareaComponent
                        rows={3}
                        label={"description"}
                        placeholder={"Description"}
                        value={openAIData.description}
                        handleChange={handleChange}
                        width={"100%"}
                    />
                </div>

            </motion.div>

        </>
    )
}

export default FormOpenAI


const InputComponent = ({ label, placeholder, value, handleChange, width }) => (
    <div class={`${`flex flex-col`} w-[${width}]`}>
        <label htmlFor={label} className='mb-[12px] text-white font-semibold cursor-pointer'>{placeholder}</label>
        <Input
            label={label}
            placeholder={placeholder}
            value={value}
            handleChange={handleChange} />
    </div>
)


const TextareaComponent = ({ rows, label, placeholder, value, handleChange, width }) => (
    <div class={`${`flex flex-col`} w-[${width}]`}>
        <label htmlFor={label} className='mb-[12px] text-white font-semibold cursor-pointer'>{placeholder}</label>
        <Textarea minRows={rows} label={label} placeholder={placeholder}
            value={value}
            handleChange={handleChange} />
    </div>
)

const DropdownComponent = ({ label, placeholder, value, handleChange, width }) => {

    return (
        <div class={`${`flex flex-col`} w-[${width}]`}>
            <label htmlFor={label} className='mb-[12px] text-white font-semibold cursor-pointer'>{placeholder}</label>
            {/* <Dropdown label={label} options={dropdownOptions} handleChange={handleChange}  /> */}
            <Dropdown label={label} options={dropdownOptions} value={value} handleChange={handleChange} />

        </div>
    )
}

const dropdownOptions = [
    {
        name: "GPT-3.5",
        value: "gpt-3.5"
    },
    {
        name: "GPT-4",
        value: "gpt-4"
    },
]
