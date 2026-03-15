<template>
	<div class="guide-page">
		<section class="guide-card">
			<RouterLink class="btn btn-link p-0 mb-3" to="/signup">
				<- Torna alla registrazione
			</RouterLink>
			<h1>Guida per ottenere API ID e API Hash</h1>
			<ol>
				<li>Assicurati di avere un account Telegram attivo.</li>
				<li>
					Vai su <a href="https://my.telegram.org/auth" target="_blank" rel="noopener noreferrer">my.telegram.org/auth</a>.
					<img src="/telegramApi.png" alt="Pagina di accesso a my.telegram.org" />
				</li>
				<li>
					Inserisci il tuo numero di telefono e premi "Next".
					<img src="/telegramApi2.png" alt="Pagina di accesso a my.telegram.org" />
				</li>
				<li>
					Inserisci il codice ricevuto su Telegram, poi premi "Sign in" e segui i passaggi indicati.
				</li>
				<li>
					Una volta ottenuti API ID e API Hash, torna su ChatControl e compila telefono,
					username e password del sito.
				</li>
				<li>Dopo l'invio, riceverai un codice nell'app Telegram.</li>
				<li>
					Se sul tuo account non e' attiva la 2FA entrerai subito. In caso contrario,
					dovrai inserire anche la password Telegram.
				</li>
			</ol>
		</section>
	</div>
</template>

<style scoped>
.guide-page {
	min-height: 100vh;
	display: flex;
	align-items: center;
	justify-content: center;
	padding: 24px 16px;
}

.guide-card {
	width: 100%;
	max-width: 720px;
	padding: 24px;
	border-radius: 12px;
	border: 1px solid #e5e7eb;
	background: #ffffff;
	box-shadow: 0 10px 24px rgba(0, 0, 0, 0.08);
}

.guide-card h1 {
	margin-bottom: 16px;
	font-size: 22px;
}

.guide-card ol {
	padding-left: 20px;
	display: grid;
	gap: 12px;
}

.guide-card img {
	display: block;
	width: 100%;
	max-width: 640px;
	margin-top: 12px;
	border-radius: 10px;
	border: 1px solid #e5e7eb;
	box-shadow: 0 8px 18px rgba(0, 0, 0, 0.08);
}

@media (max-width: 640px) {
	.guide-card {
		padding: 20px;
	}

	.guide-card h1 {
		font-size: 20px;
	}
}
</style>
