package com.homeofcode.discord;

import discord4j.core.DiscordClient;
import discord4j.core.GatewayDiscordClient;
import discord4j.core.event.domain.Event;
import reactor.core.publisher.Mono;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;

public class DiscordSimpleBot {
    static System.Logger LOG = System.getLogger(DiscordSimpleBot.class.getPackageName());
    String token;

    public DiscordSimpleBot(String token) {
        this.token = token;
    }

    private Mono<Void> setupGateway(GatewayDiscordClient g) {
        final var handlers = new HashMap<Class<? extends Event>, Method>();
        for (final Method m : this.getClass().getDeclaredMethods()) {
            if (m.isAnnotationPresent(DiscordEventHandler.class)) {
                if ((m.getModifiers() & Modifier.PUBLIC) != Modifier.PUBLIC) {
                    LOG.log(System.Logger.Level.WARNING, "skipping {0} because not public", m.getName());
                    continue;
                }
                final var eventClass = m.getAnnotation(DiscordEventHandler.class).event();
                handlers.put(eventClass, m);
            }
        }

        g.on(Event.class).subscribe(event -> handlers.forEach((clazz, method) -> {
                    if (clazz.isInstance(event)) {
                        try {
                            method.invoke(this, event);
                        } catch (IllegalAccessException | InvocationTargetException e) {
                            e.printStackTrace();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
        ));
        return Mono.empty();
    }

    public void startBot() {
        var discord = DiscordClient.create(token).withGateway(this::setupGateway);
        discord.block();
    }
}