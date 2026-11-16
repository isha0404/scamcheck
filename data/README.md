# Training data

## `SMSSpamCollection` (5,574 messages: 4,827 genuine, 747 spam)

The SMS Spam Collection v.1, a public set of real labelled SMS messages, many of them from the UK.

> Almeida, T. & Hidalgo, J. (2011). *SMS Spam Collection* [Dataset]. UCI Machine Learning Repository.
> https://doi.org/10.24432/C5CC84. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Format: one message per line, `ham` or `spam`, a tab, then the text. Included unchanged.

## `modern_uk_examples.tsv` (written for this project)

The 2012 collection is mostly prize draws and ringtone subscriptions. It contains almost none of
today's common UK scams. This file adds examples of:

- **Scams:** parcel "redelivery fees" (Royal Mail, Evri, DPD), HMRC refunds, bank "new payee" and
  "account suspended" alerts, "Hi Mum, new number", fake job offers, crypto investment, requests to
  share a security code.
- **Genuine look-alikes:** real-style delivery, bank, NHS and retailer notifications. Without these,
  the model would learn that any message mentioning a parcel is a scam.

These messages were **written by hand** to follow the patterns described in public warnings from
the NCSC, Action Fraud and UK banks. They are not real messages, and every web address is
invented. Because the set is small (about 180 messages), results on it should be read as a sanity
check, not a precise accuracy figure.
