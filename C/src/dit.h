/*
 * DIT (Data Independent Timing, Armv8.4) für load_secret_key und sign (Ebene 5, Z2).
 *
 * Mit DIT laufen die von Arm gelisteten Instruktionen (ganzzahlig, Laden/Speichern, FCSEL, …) in
 * einer von den Daten unabhängigen Zeit; auf dem Apple M3 schaltet DIT zudem den datenabhängigen
 * Prefetcher ab. Gleitkomma-Arithmetik steht nicht auf der Liste; für sie stützt sich Z2 auf die
 * Messung (ct/dudect.c). Ohne DIT-Unterstützung (andere Prozessoren, Valgrind-Build) tun die
 * Funktionen nichts.
 */
#ifndef FALCON_DIT_H
#define FALCON_DIT_H

/* Setzt DIT, falls verfügbar, und liefert den vorherigen Zustand für falcon_dit_restore. */
int falcon_dit_enable(void);

/* Stellt den Zustand vor falcon_dit_enable wieder her (bei Verschachtelung bleibt DIT an). */
void falcon_dit_restore(int previous);

/* 1, wenn DIT im aktuellen Thread gesetzt ist; 0 sonst oder ohne Unterstützung. */
int falcon_dit_active(void);

/* 1, wenn der Prozessor DIT unterstützt und es hier verwendet wird. */
int falcon_dit_supported(void);

#endif
