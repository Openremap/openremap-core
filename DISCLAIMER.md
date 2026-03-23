# Disclaimer

## Research and Educational Use Only

OpenRemap is experimental software developed for **research, educational, and
development purposes only**. It is not a commercial product, it has not been
certified or validated for use in any safety-critical or production environment,
and it is not intended for use on road-registered vehicles.

---

## Right to Repair

OpenRemap is built in the spirit of the **Right to Repair** movement. Vehicle
owners have a legitimate interest in understanding, analysing, and archiving
the firmware on hardware they legally own.

In the United States, the **DMCA (Digital Millennium Copyright Act)** grants
exemptions that allow vehicle owners to access and modify the software on their
own vehicles for the purpose of diagnosis, repair, and personalisation. These
exemptions have been renewed and expanded by the Copyright Office, most recently
in 2021.

In the European Union, the **Right to Repair Regulation (EU) 2024/1781** and
related directives affirm the right of consumers and independent repairers to
access tools and information necessary to maintain their own property.

OpenRemap does not circumvent any security system. It operates on binary files
that the user already legally possesses. Its purpose is to make the contents of
those files understandable, comparable, and reproducible — not to enable
unauthorised access to any vehicle or system.

**This framing applies only to vehicles and ECUs that you legally own or have
explicit authorisation to work on.** Using this tool on hardware you do not own
or are not authorised to modify is outside the scope of this project and is your
sole legal responsibility.

---

## No Warranty. No Guarantee of Correctness.

This software is provided **"as is"**, without warranty of any kind — express or
implied. This includes, but is not limited to, any warranty that:

- ECU identification is correct for a given binary
- Recipes are free from errors or omissions
- Patched binaries are safe, functional, or suitable for any purpose
- The software behaves as documented in all cases

The authors make no representations about the accuracy, completeness, or
reliability of any output produced by this software. **Use it at your own risk.**

---

## Professional Review is Required Before Flashing

**Any binary file produced or modified by this software must be reviewed and
verified by a qualified automotive engineer or professional ECU tuner before
it is flashed to any vehicle.**

This is not optional. The software includes post-patch validation tools to aid
this review process — but those tools are not a substitute for professional
judgement. You are responsible for ensuring that any modified firmware is safe
and appropriate for the specific vehicle and ECU it will be installed on.

Flashing incorrect, corrupted, or incompatible firmware to a vehicle ECU can
result in:

- Permanent damage to the ECU
- Engine damage
- Loss of vehicle function
- Safety hazards to the driver, passengers, and others

The authors accept no responsibility for any damage, loss, or harm arising from
the use of this software or any output it produces.

---

## ⚠️ Checksum Verification is Mandatory

> **Do not flash any binary — patched or otherwise — without first running an
> independent checksum verification.**

This is the single most important step between this tool and a vehicle. Every
ECU family uses one or more checksum algorithms to verify the integrity of its
firmware. If a checksum does not match, the ECU will reject the file, fail to
start, or enter a recovery mode — at best. At worst, it will flash corrupted
firmware silently.

**What `openremap` does NOT do:**

- It does not calculate or correct ECU checksums
- `openremap validate patched` confirms that recipe bytes were written correctly
  — it does not verify that the resulting binary is a valid, flashable image

**What you must do before flashing:**

1. Open the patched binary in a professional-grade tool — **WinOLS**, **ECM Titanium**,
   **Alientech KESS**, or an equivalent
2. Run the tool's checksum correction function for the specific ECU family
3. Confirm the binary passes integrity validation before touching any vehicle

Skipping this step can result in a permanently bricked ECU. There is no
software recovery from a bad flash on most production ECUs.

---

## Legal Responsibility Rests With the User

The legal status of modifying ECU firmware varies significantly by country,
region, and intended use. Depending on your jurisdiction, modifying engine
management software may:

- Violate **vehicle type approval** regulations (EU)
- Violate **emissions laws** such as the Clean Air Act (United States)
- Invalidate **roadworthiness certifications** (UK MOT, German TÜV, and equivalents)
- Void the vehicle manufacturer's **warranty**
- Be subject to additional regulations specific to your region

**It is your sole responsibility** to understand and comply with all applicable
laws and regulations before using this software or applying any output it
produces to a vehicle. The authors of OpenRemap provide no legal guidance and
accept no liability for regulatory or legal consequences arising from the use of
this software.

---

## Limitation of Liability

To the maximum extent permitted by applicable law, in no event shall the
authors, contributors, or copyright holders of OpenRemap be liable for any
direct, indirect, incidental, special, exemplary, or consequential damages
— including but not limited to loss of use, data, revenue, or profits;
vehicle damage; ECU damage; personal injury; or business interruption —
however caused and on any theory of liability, whether in contract, strict
liability, or tort, arising in any way out of the use of or inability to use
this software, even if advised of the possibility of such damage.

---

## Anti-Tampering

OpenRemap must not be used to perform or facilitate any of the following.
These are not tuning activities — they are criminal offences in most jurisdictions
and are explicitly outside the scope of this project:

- **Odometer fraud** — altering mileage data stored in an ECU or instrument cluster
- **Immobilizer bypass** — disabling or circumventing factory anti-theft systems
- **Safety system tampering** — modifying or disabling airbags, ABS, ESC, seatbelt
  pretensioners, or any other active or passive safety system
- **Speed limiter removal on commercial vehicles** — where governed by law
  (EU Regulation 2019/2144 and equivalents)
- **Theft facilitation** — any use that assists in the theft of a vehicle or its
  components

The authors reserve the right to refuse contributions, close issues, and remove
forks that appear to pursue any of the above purposes. If you discover that this
tool is being used for any of these activities, please report it via the
repository's security contact.

---

## Interoperability

OpenRemap is developed and distributed under the principle of **software
interoperability** as recognised by:

- **EU Directive 2009/24/EC, Article 6** — which permits the reproduction and
  translation of software code where indispensable to obtain interoperability
  of an independently created program with other programs
- **DMCA Section 1201(f)** — which provides an exemption for reverse engineering
  undertaken solely for the purpose of achieving interoperability of an
  independently created computer program
- **DMCA Section 1201(j) exemption renewals (2021)** — which extend interoperability
  and repair rights specifically to motorised land vehicles

This tool does not circumvent any copy protection or access control mechanism.
It operates exclusively on binary files that the user already legally possesses.
Its purpose is to make the contents of those files readable, comparable, and
reproducible using independently created, open-source software — which is the
definition of interoperability as intended by these provisions.

Contributors who develop extraction patterns and identification logic do so
under the same interoperability principles. Pattern matching against a binary
file you legally hold is not a circumvention act — it is the foundation of
every compatible tool in this ecosystem.

---

## Summary

| | |
|---|---|
| **Intended use** | Research, education, and development only |
| **Right to Repair** | Supported — for hardware you legally own or are authorised to work on |
| **Interoperability** | Covered under EU Directive 2009/24/EC Art. 6 and DMCA §1201(f) |
| **Anti-tampering** | Odometer fraud, immobilizer bypass, safety system disabling — prohibited |
| **Professional review** | Required before flashing any output to a vehicle |
| **Checksum verification** | Mandatory — use WinOLS, ECM Titanium, or equivalent |
| **Checksum correction** | Not performed by this tool — must be done externally |
| **Legal compliance** | Your responsibility — laws vary by jurisdiction |
| **Warranty** | None |
| **Liability** | None accepted by the authors |

If you are unsure whether using this software is legal or appropriate for your
situation, **do not use it**. Consult a qualified professional first.