# BND Command Center Alarm Sounds

This directory contains military/technical alarm sound files for the BND Command Center system.

## Required Sound Files

The following WAV files should be placed in this directory for full audio functionality:

- `beep_info.wav` - Information notification sound
- `beep_warning.wav` - Warning alert sound  
- `alarm_critical.wav` - Critical event alarm
- `alarm_emergency.wav` - Emergency shutdown alarm

## Sound File Requirements

- Format: WAV (uncompressed)
- Quality: 16-bit, 44.1kHz recommended
- Duration: 1-3 seconds for beeps, 3-5 seconds for alarms
- Style: Professional/military/technical tones (no music or voice)

## Fallback Behavior

If sound files are not present, the system will use Windows system beeps with different patterns:

- **Info**: Single 800Hz beep
- **Warning**: Double 1000Hz beep
- **Critical**: Triple 1500Hz beep sequence
- **Emergency**: Alternating 2000Hz/1000Hz beep pattern

## Sound Sources

For professional military/technical alarm sounds, consider:
- Government/military sound libraries
- Technical equipment alarm recordings
- Professional audio collections
- Custom generated technical tones

**Note**: Ensure all sound files are legally obtained and appropriately licensed for your use case.