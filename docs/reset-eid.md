# Securing your eID

The app shows this page when it recommends securing your eID: when your enrolment is refused because
someone already enrolled with your identity, when you report "it wasn't me", and when someone asks to
replace the secret on your phone without your knowing. The holder app serves the same text on its
local address at `/help/reset-eid`.

Information checked on 19 November 2026. Phone numbers and opening hours change: the provider's own
page (linked) is the one to trust.

## Why first

The app trusts whoever can log in with your eID **and** holds the app. If someone else can still log in
as you, they can lift a suspension or refuse your replacement again. Close the eID first, get a new
one, and then use the app:

1. Close (block) the eID that was used. Steps for each kind of eID are below.
2. Report the crime to the police.
3. Get new eID means from the provider.
4. In the app: `pop holder replace --not-me`, logging in with the **new** eID means.

If the suspension is lifted again after you secured your eID, someone still has a way to log in as you:
tell the police and your eID provider. (The design has an in-person desk for this case; the prototype
does not.)

## You have a right to have it closed at any time

Under Finnish law, the holder of an identification means must tell the provider without undue delay
when it is lost, in someone else's possession, or misused. The provider must make it possible to report
this **at any time** and must then revoke or block the means without delay
([Act 617/2009 § 25][s2]). EU rules require the same of every eID used for public services: it must be
possible to suspend or revoke it "in a timely and effective manner" ([Implementing Regulation (EU)
2015/1502, Annex 2.2.3][s1]).

## Bank credentials (pankkitunnukset)

Bank codes and bank apps cannot be closed from the online bank itself at Nordea; call ([Nordea][s3]).

| Bank | What to do | Number |
|---|---|---|
| Nordea | Call customer service and choose the fraud line (key 1). When it is closed, call the blocking service, open around the clock. [Nordea][s3], [Nordea credentials][s4] | customer service 0200 3000; blocking service 020 333 (+358 20 333 from abroad) |
| OP | Call customer service (weekdays 8–16). When it is closed, call the blocking service, open around the clock, and have the OP codes and card closed. [OP][s5] | 0100 0500; blocking service 0100 0555 |
| Other banks | The law above applies to every bank. Look for "sulkupalvelu" on the bank's own pages. | |

## Mobile certificate (mobiilivarmenne)

| Operator | What to do | Number |
|---|---|---|
| Elisa | Report the loss of the phone or PIN, or that someone else knows the PIN, without delay. The certificate closes when the subscription is blocked: block it yourself in OmaElisa ("Liittymän tilapäinen sulku"), or call; lost devices are taken around the clock. [Elisa FAQ][s6], [Elisa lost SIM][s7] | 010 190 240 |
| Telia | Blocking the subscription or the Mobile ID is handled as an emergency, around the clock. [Telia][s8] | 020 690 400 |

Note: a mobile certificate can be registered again with online bank codes ([Telia][s8]). If your bank
codes may also be known to someone, close those too.

## ID card certificate (kansalaisvarmenne)

If the card is lost or stolen, inform DVV's revocation service and the police; a new card is ordered
from the police ([DVV][s9]). The revocation service's number is on that page.

## Police

Identity theft is reported to the police as a crime; Nordea says the same of misused bank codes
([Nordea credentials][s4]). The report can be made online in the police e-services
(asiointi.poliisi.fi), as [Asiakastieto][s11] describes. Asiakastieto also advises contacting your bank,
changing passwords at once and considering a credit ban ([Asiakastieto][s10]).

## Sources

- s1: Commission Implementing Regulation (EU) 2015/1502, Annex, 2.2.3 "Suspension, revocation and
  reactivation" (OJ L 235, 9.9.2015), read from the copy at https://nccert.pl/files/CELEX_32015R1502_EN.pdf
- s2: Laki vahvasta sähköisestä tunnistamisesta ja sähköisistä luottamuspalveluista 617/2009, § 25,
  as amended by Act 533/2016: https://finlex.fi/api/media/statute/69585/mainPdf/main.pdf (later
  amendments not checked)
- s3: Nordea, "Toimi näin, jos epäilet tulleesi huijatuksi":
  https://www.nordea.fi/henkiloasiakkaat/sinun-elamasi/turvallisuus/jouduitko-huijatuksi.html
- s4: Nordea, "Pankkitunnukset": https://www.nordea.fi/henkiloasiakkaat/palvelumme/verkko-mobiilipalvelut/pankkitunnukset/
- s5: OP, "Turvallinen asiointi": https://www.op.fi/henkiloasiakkaat/asiakkuus/turvallisuus
- s6: Elisa, Mobiilivarmenne, usein kysyttyä: https://elisa.fi/asiakaspalvelu/aihe/mobiilivarmenne/ohje/usein-kysyttya/
- s7: Elisa, SIM tai laite kadonnut: https://elisa.fi/asiakaspalvelu/puheliittymat/sim-tai-laite-kadonnut/
- s8: Telia, Mobile certificate: https://www.telia.fi/asiakastuki/palvelut/mobile-certificate
- s9: DVV, Citizen certificate: https://dvv.fi/en/citizen-certificate
- s10: Asiakastieto, "Identiteettivarkaus – mitä tehdä aivan ensimmäisenä?":
  https://www.asiakastieto.fi/omatieto/fi/ukk/jos-havaitsen-identiteettivarkauden-mita-minun-tulee-tehda-aivan-ensimmaisena
- s11: Asiakastieto, where to file the police report:
  https://www.asiakastieto.fi/omatieto/fi/ukk/jos-ep%E4ilen-identiteettivarkautta%2C-niin-miss%E4-kohtaa-minun-kannattaa-tehd%E4-rikosilmoitus

Not read: the police's own pages (they refused automated reading), DNA and other operators, banks
other than Nordea and OP, and the DVV revocation service's number (not in the page text that could be
read).

[s1]: https://nccert.pl/files/CELEX_32015R1502_EN.pdf
[s2]: https://finlex.fi/api/media/statute/69585/mainPdf/main.pdf
[s3]: https://www.nordea.fi/henkiloasiakkaat/sinun-elamasi/turvallisuus/jouduitko-huijatuksi.html
[s4]: https://www.nordea.fi/henkiloasiakkaat/palvelumme/verkko-mobiilipalvelut/pankkitunnukset/
[s5]: https://www.op.fi/henkiloasiakkaat/asiakkuus/turvallisuus
[s6]: https://elisa.fi/asiakaspalvelu/aihe/mobiilivarmenne/ohje/usein-kysyttya/
[s7]: https://elisa.fi/asiakaspalvelu/puheliittymat/sim-tai-laite-kadonnut/
[s8]: https://www.telia.fi/asiakastuki/palvelut/mobile-certificate
[s9]: https://dvv.fi/en/citizen-certificate
[s10]: https://www.asiakastieto.fi/omatieto/fi/ukk/jos-havaitsen-identiteettivarkauden-mita-minun-tulee-tehda-aivan-ensimmaisena
[s11]: https://www.asiakastieto.fi/omatieto/fi/ukk/jos-ep%E4ilen-identiteettivarkautta%2C-niin-miss%E4-kohtaa-minun-kannattaa-tehd%E4-rikosilmoitus
