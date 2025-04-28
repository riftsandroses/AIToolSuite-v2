import * as React from 'react';
import { Radio } from '@base-ui-components/react/radio';
import { RadioGroup } from '@base-ui-components/react/radio-group';
import styles from './radioButton.module.css';



export default function RadioButton({ label, options, value, handleChange }) {
    return (
        <RadioGroup
            id={label}
            defaultValue={value}
            className={styles.RadioGroup}
            onValueChange={(newValue) => handleChange(label, newValue)}
        >

            {options.map((option, index) => {
                return (
                    <label className={styles.Item} key={index}>
                        <Radio.Root value={option.value} className={styles.Radio}>
                            <Radio.Indicator className={styles.Indicator} />
                        </Radio.Root>
                        {option.name}
                    </label>
                )
            })}


        </RadioGroup>
    );
}
